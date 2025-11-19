use ethereum_types::{Address, H256};
use primitive_types::U256;
use sha3::{Digest, Keccak256};
use std::collections::{HashMap,HashSet};
use std::fmt;
use std::str::FromStr;
use hex;


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
const JUMPI: u8 = 0x57;
const PC: u8 = 0x58;

// 区块信息指令
const BLOCKHASH:u8 = 0x40;
const COINBASE:u8  = 0x41;
const TIMESTAMP:u8  = 0x42;
const NUMBER:u8  = 0x43;
const PREVRANDAO:u8  = 0x44;
const GASLIMIT:u8  = 0x45;
const CHAINID:u8  = 0x46;
const SELFBALANCE:u8  = 0x47;
const BASEFEE:u8  = 0x48;

// 堆栈指令2
const DUP1:u8 = 0x80;
const DUP16: u8 = 0x8F;
const SWAP1:u8 = 0x90;
const SWAP16:u8 = 0x9F;

// SHA3指令
const SHA3: u8 = 0x20;

// 账户指令
const BALANCE:u8 = 0x31;
const EXTCODESIZE:u8 = 0x3B;
const EXTCODECOPY:u8 = 0x3C;
const EXTCODEHASH:u8 = 0x3F;

// 日志指令
const LOG0: u8 = 0xA0;
const LOG4: u8 = 0xA4;

// 是Rust的派生宏，让类型支持调试打印和默认值构造
#[derive(Debug, Default)] 
struct BlockInfo {
    blockhash: H256,
    coinbase: Address,
    timestamp: U256,
    number: U256,
    prevrandao: H256,
    gaslimit: U256,
    chainid: U256,
    selfbalance: U256,
    basefee: U256,
}

struct AccountInfo {
    balance: U256,
    nonce: U256,
    storage: HashMap<U256, U256>,
    code: Vec<u8>,
}

struct Log{
    address: Address,
    data: Vec<u8>,
    topics: Vec<H256>,
}
struct EVM {
    code: Vec<u8>,
    pc: usize,
    stack: Vec<U256>, // 存储32字节整数
    memory: Vec<u8>,
    storage: HashMap<U256, U256>,
    jump_destinations: HashSet<usize>,
    current_block: BlockInfo,
    account_db: HashMap<Address, AccountInfo>,
    logs: Vec<Log>,
}

impl EVM{
    fn new(code: Vec<u8>) -> Self{
        let mut jump_destinations = HashSet::new();
        for (i, byte) in code.iter().enumerate() {
            if *byte == JUMPDEST {
                jump_destinations.insert(i);
            }
        }

        // 处理区块信息
        let blockhash = H256::from_slice(&hex::decode("7527123fc877fe753b3122dc592671b4902ebf2b325dd2c7224a43c0cbeee3ca").unwrap());
        let coinbase = Address::from_slice(&hex::decode("388C818CA8B9251b393131C08a736A67ccB19297").unwrap());
        let prevrandao = H256::from_slice(&hex::decode("ce124dee50136f3f93f19667fb4198c6b94eecbacfa300469e5280012757be94").unwrap());
        let current_block = BlockInfo {
            blockhash,
            coinbase,
            timestamp: U256::from(1625900000),
            number: U256::from(17871709),
            prevrandao,
            gaslimit: U256::from(30),
            chainid: U256::from(1),
            selfbalance: U256::from(100),
            basefee: U256::from(30),
        };

        // 处理账户信息
        let mut account_db: HashMap<Address, AccountInfo> = HashMap::new();
        let address = Address::from_str("0x9bbfed6889322e016e0a02ee459d306fc19545d8").unwrap();
        let account_db_info = AccountInfo{
            balance: U256::from(100),
            nonce: U256::from(1),
            storage: HashMap::new(),
            code: vec![0x60,0x00,0x60,0x00],
        };
        account_db.insert(address, account_db_info);

        Self {
            code,
            pc: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            storage: HashMap::new(),
            jump_destinations,
            current_block,
            account_db,
            logs: Vec::new(),
        }
    }

    /// 辅助函数：将大端序字节切片转为 EVM 标准 U256（32 字节整数）
    /// EVM 要求整数是 32 字节大端序，不足 32 字节时前面补 0
    fn bytes_to_u256(data: &[u8])-> U256 {
        if data.len()>=32{
            U256::from_big_endian(&data[data.len() - 32..])
        }else{
            let mut buf = [0u8; 32];
            let offset = 32 - data.len(); // 计算需要补几个0
            if offset < 32{
                buf[offset..].copy_from_slice(data);
            }
            U256::from_big_endian(&buf)
        } 
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

    fn pop(&mut self)->U256{
        self.underflow_judge(1);
        self.stack.pop().unwrap()
    }

    /// 弹出栈顶两个元素，将相加结果push入栈
    fn add(&mut self){
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        let (result,_) = a.overflowing_add(b);
        self.stack.push(result);
    }

    /// 弹出栈顶两个元素，将元素2-元素1结果 push入栈
    fn sub(&mut self){
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        let (result,_) = b.overflowing_sub(a);
        self.stack.push(result);
    }

    // 弹出栈顶两个元素，将两元素相乘结果 push入栈
    fn mul(&mut self){
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        let (result,_) = a.overflowing_mul(b);
        self.stack.push(result);
    }

    // 弹出栈顶两个元素，将元素2/元素1结果 push入栈
    fn div(&mut self){
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        if a.is_zero(){
            panic!("不允许除0操作");
        }
        let result = b.checked_div(a).unwrap();
        self.stack.push(result);
    }

    // 弹出栈顶两个元素，元素2<元素1，push1，否则push0
    fn lt(&mut self){
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        if b < a{
            self.stack.push(U256::one());
        }else{
            self.stack.push(U256::zero());
        }
    }

    // 弹出栈顶两个元素，元素2 > 元素1，push1，否则push0
    fn gt(&mut self){
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        if b > a{
            self.stack.push(U256::one());
        }else{
            self.stack.push(U256::zero());
        }
    }
    // 弹出栈顶两个元素，元素2 == 元素1，push1，否则push0
    fn eq(&mut self){
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        if a==b {
            self.stack.push(U256::one());
        }else{
            self.stack.push(U256::zero());
        }
    }

    fn and(&mut self) {
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        self.stack.push(b & a);
    }

    fn or(&mut self) {
        self.underflow_judge(2);
        let a = self.pop();
        let b = self.pop();
        self.stack.push(b | a);
    }

    fn not(&mut self) {
        self.underflow_judge(1);
        let a = self.pop();
        self.stack.push(!a);
    }

    // 弹出栈顶两个元素，元素1为offset，元素2为value，往memory写入32字节的value
    fn mstore(&mut self){
        self.underflow_judge(2);
        let offset = self.pop().as_usize();
        let value = self.pop();
        let required_size = offset.checked_add(32).expect("memory size overflow");
        if required_size > self.memory.len(){
            // 扩展内存
            self.memory.resize(required_size, 0);
        }
        let mut buf = [0u8; 32];
        value.to_big_endian(&mut buf); // 把整数转为大端序字节数组
        self.memory[offset..required_size].copy_from_slice(&buf);
    }

    // 弹出栈顶两个元素，元素1为offset，元素2为value，往memory写入1字节的value
    fn mstore8(&mut self){
        self.underflow_judge(2);
        let offset = self.pop().as_usize();
        let value = self.pop();
        let required_size = offset.checked_add(1).expect("memory size overflow");
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
        let offset = self.pop().as_usize();
        let mut buf = [0u8; 32];
        // 安全计算从offset开始最多能读的字节数（上限32）
        let read_length = std::cmp::min(32, self.memory.len().saturating_sub(offset));
        if read_length > 0 {
            // 从内存复制数据到缓冲区（从偏移量开始，最多read_length字节）
            buf[32 - read_length..].copy_from_slice(&self.memory[offset..offset.checked_add(read_length).expect("memory size overflow")]);
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
        let key = self.pop();
        let value = self.pop();
        self.storage.insert(key,value);
    }

    // 从堆栈弹出一个元素作为key去查询Storage，将value push入栈
    fn sload(&mut self){
        self.underflow_judge(1);
        let key = self.pop();
        if let Some(value) = self.storage.get(&key){
            self.stack.push(*value);
        }else{
            self.stack.push(U256::zero());
        }
    }

    fn jump(&mut self){
        self.underflow_judge(1);
        let destination = self.pop().as_usize();
        if self.jump_destinations.contains(&destination){
            self.pc = destination;
        }else{
            panic!("Invalid JUMPDEST target");
        }
    }

    fn jump_i(&mut self){
        self.underflow_judge(2);
        let destination = self.pop().as_usize();
        let condition = self.pop();
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

    // 查询特定区块的hash
    fn blockhash(&mut self){
        self.underflow_judge(1);
        let number =  self.pop();
        if number == self.current_block.number{
            self.stack.push(U256::from_big_endian(self.current_block.blockhash.as_bytes()));
        }else{
            self.stack.push(U256::zero());
        }

    }

    fn coinbase(&mut self){
        self.stack.push(U256::from_big_endian(self.current_block.coinbase.as_bytes()));
    }

    fn timestamp(&mut self){
        self.stack.push(self.current_block.timestamp);
    }

    // 将当前区块高度压入堆栈
    fn number(&mut self){
        self.stack.push(self.current_block.number);
    }

    // 获取上一个区块的随机数输出
    fn prevrandao(&mut self){
        self.stack.push(U256::from_big_endian(self.current_block.prevrandao.as_bytes()));
    }

    fn gaslimit(&mut self){
        self.stack.push(self.current_block.gaslimit);
    }

    fn chainid(&mut self){
        self.stack.push(self.current_block.chainid);
    }

    fn selfbalance(&mut self){
        self.stack.push(self.current_block.selfbalance);
    }

    fn basefee(&mut self){
        self.stack.push(self.current_block.basefee);
    }

    fn dup(&mut self, position: usize){
        if position == 0 {
            panic!("DUP position must be >= 1");
        }
    
        self.underflow_judge(position);
        let value = self.stack[self.stack.len() - position];
        self.stack.push(value);
    }

    fn swap(&mut self, position: usize){
        self.underflow_judge(position+1);
        let stack_len = self.stack.len();
        let idx1 = stack_len - 1;
        let idx2 = stack_len - (position + 1);
        self.stack.swap(idx1, idx2);
    }

    fn sha3(&mut self){
        self.underflow_judge(2);
        let memory_offset = self.pop().as_usize();
        let size = self.pop().as_usize();
        let required_size =  memory_offset.checked_add(size).expect("memory size overflow");
        if required_size>self.memory.len(){
            self.memory.resize(required_size,0);
        }
        let data = &self.memory[memory_offset..required_size];
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let hash_value = U256::from_big_endian(&result);
        self.stack.push(hash_value);
    }

    fn balance(&mut self){
        self.underflow_judge(1);
        let addr_int = self.pop();
        // 将整数转为32字节大端序
        let mut buf = [0u8; 32];
        addr_int.to_big_endian(&mut buf);
        // 截取后20字节
        let addr_bytes = &buf[12..32];
        // 转为地址类型
        let addr = Address::from_slice(addr_bytes);
        if  let Some(account) = self.account_db.get(&addr){
            self.stack.push(account.balance);
        }else{
            self.stack.push(U256::zero());
        }
    }

    fn extcodesize(&mut self){
        self.underflow_judge(1);
        let addr_int = self.pop();
        // 将整数转为32字节大端序
        let mut buf = [0u8; 32];
        addr_int.to_big_endian(&mut buf);
        // 截取后20字节
        let addr_bytes = &buf[12..32];
        // 转为地址类型
        let addr = Address::from_slice(addr_bytes);
        if  let Some(account) = self.account_db.get(&addr){
            self.stack.push(U256::from(account.code.len() as u64));
        }else{
            self.stack.push(U256::zero());
        }
    }

    fn extcodecopy(&mut self){
        self.underflow_judge(4);

        let addr_int = self.pop();
        let mut buf = [0u8; 32];
        addr_int.to_big_endian(&mut buf);
        let addr_bytes = &buf[12..32];
        let addr = Address::from_slice(addr_bytes);

        let mem_offset = self.pop().as_usize();
        let code_offset = self.pop().as_usize();
        let length = self.pop().as_usize();

        if length==0{
            return;
        }
        let required_size = mem_offset.checked_add(length).expect("memory size overflow");
        if required_size > self.memory.len(){
            self.memory.resize(required_size,0);
        }
        
        let code_slice: &[u8] = if let Some(account)=self.account_db.get(&addr){
            &account.code
        }else{
            &[]
        };

        if code_offset>=code_slice.len(){
            return;
        }

        let available_len = code_slice.len() - code_offset;
        let to_copy_len = std::cmp::min(available_len, length);

        let src = &code_slice[code_offset..code_offset.checked_add(to_copy_len).expect("code size overflow")];
        self.memory[mem_offset..mem_offset + to_copy_len].copy_from_slice(src);
    }

    fn extcodehash(&mut self){
        self.underflow_judge(1);
        let addr_int = self.pop();
        let mut buf = [0u8; 32];
        addr_int.to_big_endian(&mut buf);
        let addr_bytes = &buf[12..32];
        let addr = Address::from_slice(addr_bytes);

        if let Some(account)=self.account_db.get(&addr){
            let code: &[u8] = &account.code;
            let mut hasher = Keccak256::new();
            hasher.update(code);
            let result = hasher.finalize();
            let result_value = U256::from_big_endian(&result);
            self.stack.push(result_value);
        }else{
            self.stack.push(U256::zero());
        };
    }

    fn logn(&mut self, num_topics:usize){
        self.underflow_judge(num_topics + 2);
        let memory_offset = self.pop().as_usize();
        let length = self.pop().as_usize();
        let mut topics = Vec::with_capacity(num_topics);
        for _ in 0..num_topics{
            let topic = self.pop();
            let mut buf = [0u8;32];
            topic.to_big_endian(&mut buf);
            topics.push(H256::from(buf));
        }
        let memory_required_size = memory_offset.checked_add(length).expect("memory size overflow");
        let data = &self.memory[memory_offset..memory_required_size];
        let log_entry=Log{
            address: self.current_block.coinbase,
            data: data.to_vec(),
            topics,
        };
        self.logs.push(log_entry);
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
                JUMPI => {
                    println!("  识别JUMPI指令");
                    self.jump_i();
                }
                PC => {
                    self.pcfn();
                }
                BLOCKHASH => {
                    println!("  识别BLOCKHASH指令");
                    self.blockhash();
                }
                COINBASE => {
                    println!("  识别COINBASE指令");
                    self.coinbase();
                }
                TIMESTAMP => {
                    println!("  识别TIMESTAMP指令");
                    self.timestamp();
                }
                NUMBER => {
                    println!("  识别NUMBER指令");
                    self.number();
                }
                PREVRANDAO => {
                    println!("  识别PREVRANDAO指令");
                    self.prevrandao();
                }
                GASLIMIT => {
                    println!("  识别GASLIMIT指令");
                    self.gaslimit();
                }
                CHAINID => {
                    println!("  识别CHAINID指令");
                    self.chainid();
                }
                SELFBALANCE => {
                    println!("  识别SELFBALANCE指令");
                    self.selfbalance();
                }
                BASEFEE => {
                    println!("  识别BASEFEE指令");
                    self.basefee();
                }
                DUP1..=DUP16 => {
                    let position = (op - DUP1 + 1) as usize;
                    self.dup(position);
                }
                SWAP1..=SWAP16 => {
                    let position = (op - SWAP1 + 1) as usize;
                    self.swap(position);
                }
                SHA3 =>{
                    self.sha3();
                }
                BALANCE =>{
                    self.balance();
                }
                EXTCODESIZE => {
                    self.extcodesize();
                }
                EXTCODECOPY => {
                    self.extcodecopy();
                }
                EXTCODEHASH => {
                    self.extcodehash();
                }
                LOG0..LOG4 =>{
                    let num_topics = (op - LOG0) as usize;
                    self.logn(num_topics);
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

        writeln!(f, "   内存Memory：")?;
        write!(f,"      ")?;
        for (_, val) in self.memory.iter().enumerate(){
            write!(f, "{:02x}",val)?;
        }

        writeln!(f,"")?;
        writeln!(f, "   存储Storage：")?;
        write!(f,"      ")?;
        for(key,value) in self.storage.iter(){
            write!(f, "{}: {}", key , value)?;
        }

        writeln!(f,"")?;
        writeln!(f, "   日志Logs:")?;
        for (i, log) in self.logs.iter().enumerate() {
            writeln!(
                f,
                "      Log {}: address={}, topics={:?}, data=0x{}",
                i,
                log.address,
                log.topics,
                hex::encode(&log.data)
            )?;
        }

        Ok(())
    }
}

fn main() {
    let code: Vec<u8> = vec![
        0x60,0xaa,
        0x60,0x00,
        0x52,
        0x60,0x11,
        0x60,0x01,
        0x60,0x1f,
        0xA1,
    ];
    let mut evm: EVM = EVM::new(code);
    evm.run();

    println!("\n{}", evm);
}