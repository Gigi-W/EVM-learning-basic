use primitive_types::U256;
use std::collections::{HashMap,HashSet};
use std::fmt;


/// EVM 官方opcode常量

// 停止指令
const STOP: u8 = 0x00;

// 堆栈指令
const PUSH0: u8 = 0x5F;
const PUSH1: u8 = 0x60;
const PUSH32: u8 = 0x7F;
const POP: u8 = 0x50;

// 算数指令
const ADD: u8 = 0x01;
const SUB: u8 = 0x03;
const MUL: u8 = 0x02;
const DIV: u8 = 0x04;

// 比较指令
const LT: u8 = 0x10;
const GT: u8 = 0x11;
const EQ: u8 = 0x14;

// 位级指令
const AND: u8 = 0x16;
const OR: u8 = 0x17;
const NOT: u8 = 0x19;

// 内存指令
const MSTORE: u8 = 0x52;
const MSTORE8: u8 = 0x53;
const MLOAD: u8 = 0x51;
const MSIZE: u8 = 0x59;

// 存储指令
const SSTORE: u8 = 0x55;
const SLOAD: u8 = 0x54;

// 跳转指令
const JUMPDEST: u8 = 0x5b;
const JUMP: u8 = 0x56;
const JUMP1: u8 = 0x57;
const PC: u8 = 0x58;

// 是Rust的派生宏，让类型支持调试打印和默认值构造
#[derive(Debug, Default)] 
struct EVM {
    code: Vec<u8>,
    pc: usize,
    stack: Vec<U256>, // 存储32字节整数
    memory: Vec<u8>,
    storage: HashMap<U256, U256>,
    jump_destinations: HashSet<usize>,
}

impl EVM{
    fn new(code: Vec<u8>) -> Self{
        let mut jump_destinations = HashSet::new();
        for (i, byte) in code.iter().enumerate() {
            if *byte == JUMPDEST {
                jump_destinations.insert(i);
            }
        }
        Self {
            code,
            pc: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            storage: HashMap::new(),
            jump_destinations,
        }
    }

    /// 辅助函数：将大端序字节切片转为 EVM 标准 U256（32 字节整数）
    /// EVM 要求整数是 32 字节大端序，不足 32 字节时前面补 0
    fn bytes_to_u256(data: &[u8])-> U256 {
        let mut buf = [0u8; 32];
        let offset = 32 - data.len(); // 计算需要补几个0
        if offset < 32{
            buf[offset..].copy_from_slice(data);
        }
        U256::from_big_endian(&buf)
    }

    fn next_instruction(&mut self) -> Option<u8>{
        if self.pc >= self.code.len(){
            return None;
        }
        let op = self.code[self.pc];
        self.pc += 1;
        Some(op)
    }

    fn underflow_judge(&mut self, count: usize){
        if self.stack.len() < count{
            panic!("堆栈下溢，至少需要{}元素, 当前{}个元素", count, self.stack.len());
        }
    }

    fn push(&mut self, size: usize){
        if self.pc + size > self.code.len(){
            panic!(
                "PUSH 指令字节不足，需要{}字节，剩余{}字节", 
                size, self.code.len() - self.pc
            );
        }
        let data = &self.code[self.pc..self.pc + size];
        let value = Self::bytes_to_u256(data);
        self.stack.push(value);
        self.pc += size;
    }

    fn pop(&mut self){
        Self::underflow_judge(self,1);
        self.stack.pop();
    }

    /// 弹出栈顶两个元素，将相加结果push入栈
    fn add(&mut self){
        Self::underflow_judge(self,2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        let (result,_) = a.overflowing_add(b);
        self.stack.push(result);
    }

    /// 弹出栈顶两个元素，将元素2-元素1结果 push入栈
    fn sub(&mut self){
        Self::underflow_judge(self,2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        let (result,_) = b.overflowing_sub(a);
        self.stack.push(result);
    }

    // 弹出栈顶两个元素，将两元素相乘结果 push入栈
    fn mul(&mut self){
        Self::underflow_judge(self,2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        let (result,_) = a.overflowing_mul(b);
        self.stack.push(result);
    }

    // 弹出栈顶两个元素，将元素2/元素1结果 push入栈
    fn div(&mut self){
        Self::underflow_judge(self,2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        if a.is_zero(){
            panic!("不允许除0操作");
        }
        let result = b.checked_div(a).unwrap();
        self.stack.push(result);
    }

    // 弹出栈顶两个元素，元素2<元素1，push1，否则push0
    fn lt(&mut self){
        Self::underflow_judge(self,2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        if b < a{
            self.stack.push(U256::one());
        }else{
            self.stack.push(U256::zero());
        }
    }

    // 弹出栈顶两个元素，元素2 > 元素1，push1，否则push0
    fn gt(&mut self){
        Self::underflow_judge(self,2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        if b > a{
            self.stack.push(U256::one());
        }else{
            self.stack.push(U256::zero());
        }
    }
    // 弹出栈顶两个元素，元素2 == 元素1，push1，否则push0
    fn eq(&mut self){
        Self::underflow_judge(self,2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        if a==b {
            self.stack.push(U256::one());
        }else{
            self.stack.push(U256::zero());
        }
    }

    fn and(&mut self) {
        self.underflow_judge(2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        self.stack.push(b & a);
    }

    fn or(&mut self) {
        self.underflow_judge(2);
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        self.stack.push(b | a);
    }

    fn not(&mut self) {
        self.underflow_judge(1);
        let a = self.stack.pop().unwrap();
        self.stack.push(!a);
    }

    // 弹出栈顶两个元素，元素1为offset，元素2为value，往memory写入32字节的value
    fn mstore(&mut self){
        self.underflow_judge(2);
        let offset = self.stack.pop().unwrap().as_usize();
        let value = self.stack.pop().unwrap();
        let required_size = offset + 32;
        if required_size > self.memory.len(){
            // 扩展内存
            self.memory.resize(required_size, 0);
        }
        let mut buf = [0u8; 32];
        value.to_big_endian(&mut buf); // 把整数转为大端序字节数组
        self.memory[offset..offset + 32].copy_from_slice(&buf);
    }

    // 弹出栈顶两个元素，元素1为offset，元素2为value，往memory写入1字节的value
    fn mstore8(&mut self){
        self.underflow_judge(2);
        let offset = self.stack.pop().unwrap().as_usize();
        let value = self.stack.pop().unwrap();
        let required_size = offset + 1;
        if required_size > self.memory.len(){
            // 扩展内存
            self.memory.resize(required_size, 0);
        }
        let byte_value = (value.low_u64() & 0xFF) as u8;
        self.memory[offset] = byte_value;
    }

    // 弹出栈顶一个元素作为offset，从内存offset的位置加载32字节，再push入栈
    fn mload(&mut self){
        self.underflow_judge(1);
        let offset = self.stack.pop().unwrap().as_usize();
        let mut buf = [0u8; 32];
        // 安全计算计算从offset开始最多能读的字节数（上限32）
        let read_length = std::cmp::min(32, self.memory.len().saturating_sub(offset));
        if read_length > 0 {
            // 从内存复制数据到缓冲区（从偏移量开始，最多read_length字节）
            buf[32 - read_length..].copy_from_slice(&self.memory[offset..offset + read_length]);
        }
        let value = U256::from_big_endian(&buf);
        self.stack.push(value);
    }

    // 将内存长度push入栈
    fn msize(&mut self){
        self.stack.push(U256::from(self.memory.len()));
    }

    // 从堆栈弹出两个元素，元素1为key，元素2为value，放入Storage
    fn sstore(&mut self){
        self.underflow_judge(2);
        let key = self.stack.pop().unwrap();
        let value = self.stack.pop().unwrap();
        self.storage.insert(key,value);
    }

    // 从堆栈弹出一个元素作为key去查询Storage，将value push入栈
    fn sload(&mut self){
        self.underflow_judge(1);
        let key = self.stack.pop().unwrap();
        if let Some(value) = self.storage.get(&key){
            self.stack.push(*value);
        }else{
            self.stack.push(U256::zero());
        }
    }

    fn jump(&mut self){
        self.underflow_judge(1);
        let destination = self.stack.pop().unwrap().as_usize();
        if self.jump_destinations.contains(&destination){
            self.pc = destination;
        }else{
            panic!("Invalid JUMPDEST target");
        }
    }

    fn jump1(&mut self){
        self.underflow_judge(2);
        let destination = self.stack.pop().unwrap().as_usize();
        let condition = self.stack.pop().unwrap();
        if !condition.is_zero(){
            if self.jump_destinations.contains(&destination){
                self.pc = destination;
            }else{
                panic!("Invalid JUMPDEST target");
            }
        }
    }

    fn pcfn(&mut self) {
        self.stack.push(U256::from(self.pc));
    }

    fn run(&mut self){
        println!("开始执行字节码，初始pc: {}", self.pc);
        while let Some(op) = self.next_instruction(){
            println!("当前opcode为：0x{:02x}", op);
            match op{
                STOP => {
                    println!("程序终止");
                    break;
                }
                PUSH1..=PUSH32 => {
                    let size = ((op-PUSH1) + 1) as usize;
                    println!("  识别PUSH{}指令，操作数长度：{}字节", size, size);
                    self.push(size);
                }
                PUSH0 => {
                    println!("  识别PUSH0指令，压入0");
                    self.stack.push(U256::zero());
                }
                POP => {
                    println!("  识别POP指令");
                    self.pop();
                }
                ADD => {
                    println!("  识别ADD指令");
                    self.add();
                }
                SUB => {
                    println!("  识别SUB指令");
                    self.sub();
                }
                MUL => {
                    println!("  识别MUL指令");
                    self.mul();
                }
                DIV => {
                    println!("  识别DIV指令");
                    self.div();
                }
                LT => {
                    println!("  识别LT指令");
                    self.lt();
                }
                GT => {
                    println!("  识别GT指令");
                    self.gt();
                }
                EQ => {
                    println!("  识别EQ指令");
                    self.eq();
                }
                AND => { // 新增：与指令
                    println!("  识别AND指令");
                    self.and();
                }
                OR => {
                    println!("  识别OR指令");
                    self.or();
                }
                NOT => {
                    println!("  识别NOT指令");
                    self.not();
                }
                MSTORE => { 
                    println!("  识别MSTORE指令");
                    self.mstore();
                }
                MSTORE8 => { 
                    println!("  识别MSTORE8指令");
                    self.mstore8();
                }
                MLOAD => { 
                    println!("  识别MLOAD指令");
                    self.mload();
                }
                MSIZE => { 
                    println!("  识别MSIZE指令");
                    self.msize();
                }
                SSTORE => {
                    println!("  识别SSTORE指令");
                    self.sstore();
                }
                SLOAD => {
                    println!("  识别SLOAD指令");
                    self.sload();
                }
                JUMPDEST => {
                    println!("  识别JUMPDEST指令");
                }
                JUMP => {
                    println!("  识别JUMP指令");
                    self.jump();
                }
                JUMP1 => {
                    println!("  识别JUMP1指令");
                    self.jump1();
                }
                PC => {
                    self.pcfn();
                }
                _ => println!("不支持的opcode：{}", op),
            }
            println!("  执行完毕后，pc:{}，堆栈长度：{}", self.pc, self.stack.len());
        }
        println!("字节码执行完毕！")
    }
}

// 自定义堆栈输出格式
impl fmt::Display for EVM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        writeln!(f, "EVM 最终状态:")?;
        writeln!(f,"    字节码长度：{}字节", self.code.len())?;
        writeln!(f,"    程序计数器：{}",  self.pc)?;
        writeln!(f,"    堆栈（栈底——>栈顶）：")?;
        for (i, val) in self.stack.iter().enumerate(){
            writeln!(
                f,
                "           第 {} 位 默认十进制={}, 十六进制=0x{:x}",
                i,
                val,
                val
            )?;
        }

        writeln!(f, "   内存：")?;
        write!(f,"      ")?;
        for (_, val) in self.memory.iter().enumerate(){
            write!(f, "{}",val)?;
        }

        writeln!(f, "   存储：")?;
        write!(f,"      ")?;
        for(key,value) in self.storage.iter(){
            write!(f, "{}: {}", key , value)?;
        }
        Ok(())
    }
}

fn main() {
    let code: Vec<u8> = vec![
        0x60, 0x02,
        0x60, 0x20,
        0x00,
        0x60, 0x20,
        0x54
    ];
    let mut evm: EVM = EVM::new(code);
    evm.run();

    println!("\n{}", evm);
}