use primitive_types::U256;
use std::fmt;


// EVM 官方opcode常量
const PUSH0: u8 = 0x5F;
const PUSH1: u8 = 0x60;
const PUSH32: u8 = 0x7F;
const POP: u8 = 0x50;
const ADD: u8 = 0x01;
const SUB: u8 = 0x03;
const MUL: u8 = 0x02;
const DIV: u8 = 0x04;

// 是Rust的派生宏，让类型支持调试打印和默认值构造
#[derive(Debug, Default)] 
struct EVM {
    code: Vec<u8>,
    pc: usize,
    stack: Vec<U256>, // 存储32字节整数
}

impl EVM{
    fn new(code: Vec<u8>) -> Self{
        Self {
            code,
            pc: 0,
            stack: Vec::new(),
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
        if self.stack.len()==0{
            panic!("堆栈下溢，至少需要1个元素");
        }
        self.stack.pop();
    }

    fn add(&mut self){
        if self.stack.len()<2{
            panic!("堆栈下溢，至少需要两个元素");
        }
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        let (result,_) = a.overflowing_add(b);
        self.stack.push(result);
    }

    fn sub(&mut self){
        if self.stack.len()<2{
            panic!("堆栈下溢，至少需要两个元素");
        }
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        let (result,_) = b.overflowing_sub(a);
        self.stack.push(result);
    }

    fn mul(&mut self){
        if self.stack.len()<2{
            panic!("堆栈下溢，至少需要两个元素");
        }
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        let (result,_) = a.overflowing_mul(b);
        self.stack.push(result);
    }

    fn div(&mut self){
        if self.stack.len()<2{
            panic!("堆栈下溢，至少需要两个元素");
        }
        let a = self.stack.pop().unwrap();
        let b = self.stack.pop().unwrap();
        if a.is_zero(){
            panic!("不允许除0操作");
        }
        let result = b.checked_div(a).unwrap();
        self.stack.push(result);
    }

    fn run(&mut self){
        println!("开始执行字节码，初始pc: {}", self.pc);
        while let Some(op) = self.next_instruction(){
            println!("当前opcode为：0x{:02x}", op);
            match op{
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
        Ok(())
    }
}

fn main() {
    let code: Vec<u8> = vec![
        0x60, 0x05,
        0x60, 0x03,
        0x04
    ];
    let mut evm: EVM = EVM::new(code);
    evm.run();

    println!("\n{}", evm);
}
