#![feature(ascii_char)]
#![allow(dead_code)]

mod vec_deque_expansion {
    use std::collections::VecDeque;
    pub fn consume_u8(d: &mut VecDeque<u8>) -> Option<u8> {
        if d.is_empty() {
            return None;
        }
        let tmp: [u8; 1] = [
            d.pop_front().unwrap()
        ];
        Some(u8::from_le_bytes(tmp))
    }
    pub fn consume_u16(d: &mut VecDeque<u8>) -> Option<u16> {
        if d.len() < 2 {
            return None;
        }
        let tmp: [u8; 2] = [
            d.pop_front().unwrap(),
            d.pop_front().unwrap()
        ];
        Some(u16::from_le_bytes(tmp))
    }
    pub fn consume_u32(d: &mut VecDeque<u8>) -> Option<u32> {
        if d.len() < 4 {
            return None;
        }
        let tmp: [u8; 4] = [
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap()
        ];
        Some(u32::from_le_bytes(tmp))
    }
    pub fn consume_u64(d: &mut VecDeque<u8>) -> Option<u64> {
        if d.len() < 8 {
            return None;
        }
        let tmp: [u8; 8] = [
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap(),
            d.pop_front().unwrap()
        ];
        Some(u64::from_le_bytes(tmp))
    }
    pub fn consume_vec(d: &mut VecDeque<u8>, len: usize) -> Option<Vec<u8>>{
        if d.len() < len {
            return None;
        }
        let mut f: Vec<u8> = Vec::new();
        for _ in 0..len {
            f.push(d.pop_front().unwrap());
        }
        Some(f.clone())
    }
}

mod elf{
    use std::collections::VecDeque;
    use crate::vec_deque_expansion::*;
    #[derive(Debug, Default, Clone)]
    #[repr(C)]
    pub struct ElfHeader{
        /// a 4-byte magic number that should be equal to [0x7f, 'E', 'L', 'F']
        pub e_ident_magic: u32,

        /// a 1-byte field that indicates the machine type since we only support
        /// 64-bit, anything that's 32-bit should die.
        /// 1 | 32-bit
        /// 2 | 64-bit
        pub e_ident_class: u8,

        /// a 1-byte field that indicates the machine endianness
        /// 1 | little-endian
        /// 2 | big-endian
        pub e_ident_data: u8,

        /// a 1-byte field that indicates the elf version. only `1` is valid.
        pub e_ident_version: u8,

        /// a 1-byte field that indicates the OS-ABI
        /// 0x00 | SystemV
        /// 0x01 | HP-UX
        /// 0x02 | NetBSD
        /// 0x03 | Linux
        /// 0x04 | GNU Hurd
        /// 0x06 | Solaris
        /// 0x07 | AIX(Monterey)
        /// 0x08 | IRIX
        /// 0x09 | FreeBSD
        /// 0x0A | Tru64
        /// 0x0B | Novell Modesto
        /// 0x0C | OpenBSD
        /// 0x0D | OpenVMS
        /// 0x0E | NonStop Kernel
        /// 0x0F | AROS
        /// 0x10 | FenixOS
        /// 0x11 | Nuix CloudABI
        /// 0x12 | Stratus Technologies OpenVOS
        pub e_ident_os_abi: u8,

        /// Ignored, because it's too complicated for me to try to figure out.
        pub e_ident_abi_version: u8,

        /// Padding
        pub e_ident_pad: [u8; 7],

        /// object file type
        /// 0x0000 | ET_NONE   | Unknown
        /// 0x0001 | ET_REL    | Relocatable file
        /// 0x0002 | ET_EXEC   | Executable file
        /// 0x0003 | ET_DYN    | Shared object
        /// 0x0004 | ET_CORE   | Core file
        /// 0xFE00 | ET_LOOS   | Reserved inclusive range start OS Specific
        /// 0xFEFF | ET_HIOS   | Reserved inclusive range end OS Specific
        /// 0xFF00 | ET_LOPROC | Reserved inclusive range start Processor Specific
        /// 0xFFFF | ET_HIPROC | Reserved inclusive range end Processor Specific
        pub e_type: u16,

        /// machine type
        /// 0x00        | No specific instruction set
        /// 0x01        | AT&T WE 32100
        /// 0x02        | SPARC
        /// 0x03        | x86
        /// 0x04        | Motorola 68000 (M68k)
        /// 0x05        | Motorola 88000 (M88k)
        /// 0x06        | Intel MCU
        /// 0x07        | Intel 80860
        /// 0x08        | MIPS
        /// 0x09        | IBM System/370
        /// 0x0A        | MIPS RS3000 Little-endian
        /// 0x0B - 0x0E | Reserved for future use
        /// 0x0F        | Hewlett-Packard PA-RISC
        /// 0x13        | Intel 80960
        /// 0x14        | PowerPC
        /// 0x15        | PowerPC (64-bit)
        /// 0x16        | S390, including S390x
        /// 0x17        | IBM SPU/SPC
        /// 0x18 - 0x23 | Reserved for future use
        /// 0x24        | NEC V800
        /// 0x25        | Fujitsu FR20
        /// 0x26        | TRW RH-32
        /// 0x27        | Motorola RCE
        /// 0x28        | Arm (up to Armv7/AArch32)
        /// 0x29        | Digital Alpha
        /// 0x2A        | SuperH
        /// 0x2B        | SPARC Version 9
        /// 0x2C        | Siemens TriCore embedded processor
        /// 0x2D        | Argonaut RISC Core
        /// 0x2E        | Hitachi H8/300
        /// 0x2F        | Hitachi H8/300H
        /// 0x30        | Hitachi H8S
        /// 0x31        | Hitachi H8/500
        /// 0x32        | IA-64
        /// 0x33        | Stanford MIPS-X
        /// 0x34        | Motorola ColdFire
        /// 0x35        | Motorola M68HC12
        /// 0x36        | Fujitsu MMA Multimedia Accelerator
        /// 0x37        | Siemens PCP
        /// 0x38        | Sony nCPU embedded RISC processor
        /// 0x39        | Denso NDR1 microprocessor
        /// 0x3A        | Motorola Star*Core processor
        /// 0x3B        | Toyota ME16 processor
        /// 0x3C        | STMicroelectronics ST100 processor
        /// 0x3D        | Advanced Logic Corp. TinyJ embedded processor family
        /// 0x3E        | AMD x86-64
        /// 0x3F        | Sony DSP Processor
        /// 0x40        | Digital Equipment Corp. PDP-10
        /// 0x41        | Digital Equipment Corp. PDP-11
        /// 0x42        | Siemens FX66 microcontroller
        /// 0x43        | STMicroelectronics ST9+ 8/16 bit microcontroller
        /// 0x44        | STMicroelectronics ST7 8-bit microcontroller
        /// 0x45        | Motorola MC68HC16 Microcontroller
        /// 0x46        | Motorola MC68HC11 Microcontroller
        /// 0x47        | Motorola MC68HC08 Microcontroller
        /// 0x48        | Motorola MC68HC05 Microcontroller
        /// 0x49        | Silicon Graphics SVx
        /// 0x4A        | STMicroelectronics ST19 8-bit microcontroller
        /// 0x4B        | Digital VAX
        /// 0x4C        | Axis Communications 32-bit embedded processor
        /// 0x4D        | Infineon Technologies 32-bit embedded processor
        /// 0x4E        | Element 14 64-bit DSP Processor
        /// 0x4F        | LSI Logic 16-bit DSP Processor
        /// 0x8C        | TMS320C6000 Family
        /// 0xAF        | MCST Elbrus e2k
        /// 0xB7        | Arm 64-bits (Armv8/AArch64)
        /// 0xDC        | Zilog Z80
        /// 0xF3        | RISC-V
        /// 0xF7        | Berkeley Packet Filter
        /// 0x101       | WDC 65C816
        pub e_machine: u16,
        
        /// set to 1 for original version of elf
        pub e_version: u32,
        
        /// Entry point of the elf. It the elf shouldn't have an entry point, 
        /// this field holds `0x0000000000000000`
        pub e_entry: u64,

        /// Points to the start of the program header table.
        pub e_phoff: u64,

        /// Points to the start of the section header.
        pub e_shoff: u64,

        /// Interpretation of this field depends on the target architecture.
        /// We `probably` ignore this.
        pub e_flags: u32,

        /// Contains the size of the Elf header. (64-bytes for 64-bit, and
        /// 52-bytes for 32-bit)
        pub e_ehsize: u16,

        /// Contains the size of a program hader table entry.
        pub e_phentsize: u16,

        /// Contains the number of entries in the program header table.
        pub e_phnum: u16,

        /// Contains the size of a section header table entry.
        pub e_shentsize: u16,

        /// Contains the number of entries in the section header table.
        pub e_shnum: u16,

        /// Contains index of the section header table entry that contains the 
        /// section names.
        pub e_shstrndx: u16,
    }

    #[derive(Debug, Default, Clone)]
    #[repr(C)]
    pub struct ProgramHeader{
        /// Identifies the type of the segment.
        /// 0x00000000  | PT_NULL    | Program header table entry unused.
        /// 0x00000001  | PT_LOAD    | Loadable segment.
        /// 0x00000002  | PT_DYNAMIC | Dynamic linking information.
        /// 0x00000003  | PT_INTERP  | Interpreter information.
        /// 0x00000004  | PT_NOTE    | Auxiliary information.
        /// 0x00000005  | PT_SHLIB   | Reserved.
        /// 0x00000006  | PT_PHDR    | Segment containing program header table
        /// 0x00000007  | PT_TLS     | Thread-Local Storage template.
        /// 0x60000000  | PT_LOOS    | Start of reserved range. OS specific.
        /// 0x6FFFFFFF  | PT_HIOS    | End of reserved range. OS specific.
        /// 0x70000000  | PT_LOPROC  | Start of reserved range. Processor specific.
        /// 0x7FFFFFFF  | PT_HIPROC  | End of reserved range. Processor specific.
        pub p_type: u32,

        /// Segment-dependent flags (position for 64-bit structure).
        /// 0x1 | PF_X | Executable segment.
        /// 0x2 | PF_W | Writeable segment.
        /// 0x4 | PF_R | Readable segment.
        pub p_flags: u32,

        /// Offset of the segment in the file image.
        pub p_offset: u64,

        /// Virtual address of the segment in memory.
        pub p_vaddr: u64,

        /// On systems where physical address is relevant, reserved for 
        /// segment's physical address.
        pub p_paddr: u64,

        /// Size in bytes of the segment in the file image. May be `0`
        pub p_filesz: u64,

        /// Size in bytes of the segment in memory. May be `0`
        pub p_memsz: u64,

        /// Indicates the alignment of the section. `0` and `1` specify no
        /// alignment. Otherwise, should be a positive, integral power of `2`,
        /// with p_vaddr equating p_offset modulus p_align.
        pub p_align: u64,
    }

    #[derive(Debug, Default, Clone)]
    #[repr(C)]
    pub struct SectionHeader{
        /// An offset to a string in the .shstrtab section that represents the 
        /// name of this section.
        pub sh_name: u32,

        /// Identifies the type of this header.
        /// 0x0        | SHT_NULL           | Section header table entry unused
        /// 0x1        | SHT_PROGBITS       | Program data
        /// 0x2        | SHT_SYMTAB         | Symbol table
        /// 0x3        | SHT_STRTAB         | String table
        /// 0x4        | SHT_RELA           | Relocation entries with addends
        /// 0x5        | SHT_HASH           | Symbol hash table
        /// 0x6        | SHT_DYNAMIC        | Dynamic linking information
        /// 0x7        | SHT_NOTE           | Notes
        /// 0x8        | SHT_NOBITS         | Program space with no data (bss)
        /// 0x9        | SHT_REL            | Relocation entries, no addends
        /// 0x0A       | SHT_SHLIB          | Reserved
        /// 0x0B       | SHT_DYNSYM         | Dynamic linker symbol table
        /// 0x0E       | SHT_INIT_ARRAY     | Array of constructors
        /// 0x0F       | SHT_FINI_ARRAY     | Array of destructors
        /// 0x10       | SHT_PREINIT_ARRAY  | Array of pre-constructors
        /// 0x11       | SHT_GROUP          | Section group
        /// 0x12       | SHT_SYMTAB_SHNDX   | Extended section indices
        /// 0x13       | SHT_NUM            | Number of defined types.
        /// 0x60000000 | SHT_LOOS           | Start OS-specific.
        /// ...        | ...                | ...
        pub sh_type: u32,

        /// Identifies the attributes of the section.
        /// 0x1        | SHF_WRITE            | Writable
        /// 0x2        | SHF_ALLOC            | Occupies memory during execution
        /// 0x4        | SHF_EXECINSTR        | Executable
        /// 0x10       | SHF_MERGE            | Might be merged
        /// 0x20       | SHF_STRINGS          | Contains null-terminated strings
        /// 0x40       | SHF_INFO_LINK        | 'sh_info' contains SHT index
        /// 0x80       | SHF_LINK_ORDER       | Preserve order after combining
        /// 0x100      | SHF_OS_NONCONFORMING | Non-standard OS specific 
        ///                                   | handling required
        /// 0x200      | SHF_GROUP            | Section is member of a group
        /// 0x400      | SHF_TLS              | Section hold thread-local data
        /// 0x0FF00000 | SHF_MASKOS           | OS-specific
        /// 0xF0000000 | SHF_MASKPROC         | Processor-specific
        /// 0x4000000  | SHF_ORDERED          | Special ordering requirement 
        ///                                   | (Solaris)
        /// 0x8000000  | SHF_EXCLUDE          | Section is excluded unless 
        ///                                   | referenced or allocated (Solaris)
        pub sh_flags: u64,

        /// Virtual address of the section in memory, for sections that are loaded.
        pub sh_addr: u64,

        /// Offset of the section in the file image.
        pub sh_offset: u64,

        /// Size in bytes of the section in the file image. May be `0`
        pub sh_size: u64,

        /// Contains the section index of an associated section. This field is
        /// used for several purposes, depending on the type of section.
        pub sh_link: u32,

        /// Contains extra information about the section. This field is used
        /// for several purposes depending on the type of section.
        pub sh_info: u32,

        /// Contians the required alignment of the section. This field must be a
        /// power of two.
        pub sh_addralign: u64,

        /// Contains the size, in bytes, of each entry, for sections that contain
        /// fixed-size entries. Otherwise, this field contains `0x0000000000000000`
        pub sh_entsize: u64,

    }

    pub fn parse_elf_header(d: &mut VecDeque<u8>) -> Option<ElfHeader>{
        if d.len() < (std::mem::size_of::<ElfHeader>()) {
            return None;
        }
        Some(
            ElfHeader{
                e_ident_magic: consume_u32(d)?,
                e_ident_class: consume_u8(d)?, 
                e_ident_data: consume_u8(d)?,
                e_ident_version: consume_u8(d)?,
                e_ident_os_abi: consume_u8(d)?,
                e_ident_abi_version: consume_u8(d)?,
                e_ident_pad: consume_vec(d, 7)?.try_into().unwrap(),
                e_type: consume_u16(d)?,
                e_machine: consume_u16(d)?,
                e_version: consume_u32(d)?,
                e_entry: consume_u64(d)?,
                e_phoff: consume_u64(d)?,
                e_shoff: consume_u64(d)?,
                e_flags: consume_u32(d)?,
                e_ehsize: consume_u16(d)?,
                e_phentsize: consume_u16(d)?,
                e_phnum: consume_u16(d)?,
                e_shentsize: consume_u16(d)?,
                e_shnum: consume_u16(d)?,
                e_shstrndx: consume_u16(d)?,
            }
        )
    }

    pub fn parse_program_header(d: &mut VecDeque<u8>) -> Option<ProgramHeader> {
        Some(
            ProgramHeader{
                p_type: consume_u32(d)?,
                p_flags: consume_u32(d)?,
                p_offset: consume_u64(d)?,
                p_vaddr: consume_u64(d)?,
                p_paddr: consume_u64(d)?,
                p_filesz: consume_u64(d)?,
                p_memsz: consume_u64(d)?,
                p_align: consume_u64(d)?,
            }
        )
    }

    pub fn parse_section_header(d: &mut VecDeque<u8>) -> Option<SectionHeader> {
        Some(
                SectionHeader{
                    sh_name: consume_u32(d)?,
                    sh_type: consume_u32(d)?,
                    sh_flags: consume_u64(d)?,
                    sh_addr: consume_u64(d)?,
                    sh_offset: consume_u64(d)?,
                    sh_size: consume_u64(d)?,
                    sh_link: consume_u32(d)?,
                    sh_info: consume_u32(d)?,
                    sh_addralign: consume_u64(d)?,
                    sh_entsize: consume_u64(d)?,
                }
            )

    }
}



#[cfg(test)]
mod tests {
    use std::io::{Write, Read, Stdout};
    use std::fs::{File, Metadata};
    use std::collections::{VecDeque, HashMap};
    use crate::elf::*;
    use crate::vec_deque_expansion::*;

    pub fn pri(mut l: &Stdout, s: &str) {
        let out = format!("  {}:{}:{} :: [+] : {}",
                          file!(), 
                          line!(), 
                          column!(), 
                          s);
        let _ = writeln!(l, "{}", out.clone());
    }

    fn get_str_from_index(d: &[u8], indx: usize) -> Option<&str>{
        if indx > d.len() {
            return None;
        }
        let mut j: usize = indx;
        for i in indx..d.len() {
            if d[i] == 0 {
                return Some(d[indx..j].as_ascii()?.as_str());
            }
            j += 1;
        }
        Some(d[indx..j].as_ascii()?.as_str())
    }


    #[test]
    fn parse() {
        let mut lock = std::io::stdout();
        let mut f: File = File::open("/bin/bash").unwrap();
        let metadata: Metadata = f.metadata().unwrap();
        let mut master_bytes: Vec<u8> = 
            Vec::<u8>::with_capacity(metadata.len() as usize);
        master_bytes.resize(metadata.len() as usize, 0);
        let bin_size: usize = f.read(&mut master_bytes)
            .map_err(|_x| usize::MAX).unwrap();
        let mut bytes: VecDeque<u8> = VecDeque::<u8>::from(master_bytes.clone());
		
        pri(&mut lock, &format!("Successfully read {} bytes!", bin_size));
        let elf_header: ElfHeader = parse_elf_header(&mut bytes).unwrap(); 
        pri(&mut lock, &format!("{0:#x?}", elf_header));
        let mut program_headers: Vec<ProgramHeader> = 
            Vec::<ProgramHeader>::with_capacity(elf_header.e_phnum as usize);
        program_headers.resize(elf_header.e_phnum as usize, ProgramHeader::default());
        pri(&mut lock, &format!("program has: {:#x} Program Headers.",
                                program_headers.len()));
        let mut bytes: VecDeque<u8> = master_bytes.clone()
            .drain(elf_header.e_phoff as usize..).collect::<VecDeque<u8>>();
        for i in 0..program_headers.len() {
            program_headers[i] = parse_program_header(&mut bytes).unwrap();
        }
        pri(&mut lock, &format!("{0:#x?}", program_headers));

        let mut section_headers: Vec<SectionHeader> = 
            Vec::<SectionHeader>::with_capacity(elf_header.e_shnum as usize);
        section_headers.resize(elf_header.e_shnum as usize, SectionHeader::default());
        pri(&mut lock, &format!("program has: {:#x} Section Headers.",
                                section_headers.len()));
        let mut bytes: VecDeque<u8> = master_bytes.clone()
            .drain(elf_header.e_shoff as usize..).collect::<VecDeque<u8>>();
        
        for i in 0..section_headers.len() {
            section_headers[i] = parse_section_header(&mut bytes).unwrap();
        }
        pri(&mut lock, &format!("{0:#x?}", section_headers));
        let str_header: SectionHeader = 
            section_headers[elf_header.e_shstrndx as usize].clone();
        let bytes: VecDeque<u8> = master_bytes.clone()
            .drain(str_header.sh_offset as usize..)
            .collect::<VecDeque<u8>>();
        let mut str_buff: Vec<u8> = Vec::<u8>::with_capacity(str_header.sh_size as usize);
        str_buff.resize(str_header.sh_size as usize, 0u8);
        for i in 0..str_buff.len() {
            str_buff[i] = bytes[i];
        }
        let mut section_headers_map: HashMap<&str, SectionHeader> = HashMap::<&str, SectionHeader>::new();
        for h in section_headers {
            section_headers_map.insert(get_str_from_index(&str_buff, h.sh_name as usize).unwrap(), h);
        }
        for h in section_headers_map.keys() {
            pri(&lock, &format!("{} {:#x?}", h, section_headers_map.get(h).unwrap()));
        }

    }
}
