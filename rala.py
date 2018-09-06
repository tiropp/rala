import argparse
import struct
import io
from collections import defaultdict


class Error(Exception):
    pass


class Utils:
    def read_byte(f):
        return Utils._raw_read_integer(f, 1)
    
    def read_word(f):
        v = Utils._raw_read_integer(f, 2)
        return struct.unpack("=H", struct.pack(">H", v))[0]

    def read_string(f):
        length = Utils.read_byte(f)
        byte_string = f.read(length)
        string = byte_string.decode("utf-8")
        return string

    def read_all(f):
        return f.read()
            
    def read_raw(f, size):
        return f.read(size)
    
    def _raw_read_integer(f, size):
        return int(Utils.read_raw(f, size).hex(), 16)

    
class SegType:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        if   self.value == 0: return "0-CODE"
        elif self.value == 1: return "1-XDATA"
        elif self.value == 2: return "2-DATA"
        elif self.value == 3: return "3-IDATA"
        elif self.value == 4: return "4-BIT"
        else: raise Error("Seg Type value %s invalid" % self.value)
    
            
class SegInfo:
    def __init__(self, value):
        self.value    = value
        self.seg_type = SegType(0x07 & value)
        self.seg_reg  = 0x18 & value
        self.ovl      = 0x20 & value
        self.e        = 0x80 & value

    def __str__(self):
        return "value:{value}## seg_type:{seg_type}, seg_reg:{seg_reg}, ovl:{ovl}, e:{e}".format(
            value    = self.value,
            seg_type = self.seg_type,
            seg_reg  = self.seg_reg,
            ovl      = self.ovl,
            e        = self.e
            )

    
class UsageType:
    CODE = 0
    XDATA = 1
    DATA = 2
    IDATA = 3
    BIT = 4
    NUMBER = 5
    
    def __init__(self, value):
        self.value = value

    def __str__(self):
        if   self.is_code():   return "0-CODE"
        elif self.is_xdata():  return "1-XDATA"
        elif self.is_data():   return "2-DATA"
        elif self.is_idata():  return "3-IDATA"
        elif self.is_bit():    return "4-BIT"
        elif self.is_number(): return "5-NUMBER"
        else: raise Error("UsageType value %s invalid" % self.value)

    def get_type(self):
        return self.value

    def is_code(self):
        "Returns true if this is a CODE UsageType"
        return self.value == UsageType.CODE

    def is_xdata(self):
        return self.value == UsageType.XDATA

    def is_data(self):
        return self.value == UsageType.DATA

    def is_idata(self):
        return self.value == UsageType.IDATA

    def is_bit(self):
        return self.value == UsageType.BIT

    def is_number(self):
        return self.value == UsageType.NUMBER
        

class SymInfo:
    def __init__(self, value):
        self.value = value
        self.usage_type = UsageType(0x07 & value)
        self.sym_reg    = 0x18 & value
        self.rbf        = 0x20 & value
        self.var        = 0x40 & value
        self.ind        = 0x80 & value

    def __str__(self):
        return "value:{value}## usage_type:{usage_type}, sym_reg:{sym_reg}, rbf:{rbf}, var:{var}, ind:{ind}".format(
            value      = self.value,
            usage_type = self.usage_type,
            sym_reg    = self.sym_reg,
            rbf        = self.rbf,
            var        = self.var,
            ind        = self.ind
            )

    def is_code(self):
        "Returns true if this symbol is of type CODE"
        return self.usage_type.is_code()

    def is_xdata(self):
        return self.usage_type.is_xdata()

    def is_data(self):
        return self.usage_type.is_data()

    def is_idata(self):
        return self.usage_type.is_idata()

    def is_bit(self):
        return self.usage_type.is_bit()

    def is_number(self):
        return self.usage_type.is_number()
    
    
    
class ModuleHeaderRecord:
    def __init__(self, module_name, trn_id):
        self.module_name = module_name
        self.trn_id      = trn_id

    def __str__(self):
        return "ModuleHeaderRecord: module_name:{module_name}, trn_id:{trn_id}".format(
            module_name = self.module_name,
            trn_id      = self.trn_id
            )
    

class ModuleEndRecord:
    def __init__(self, module_name, reg_mask):
        self.module_name = module_name
        self.reg_mask    = reg_mask

    def __str__(self):
        return "ModuleEndRecord: module_name:{module_name}, reg_mask:{reg_mask}".format(
            module_name = self.module_name,
            reg_mask    = self.reg_mask
            )
    
    
class SegmentDefsRecord:
    def __init__(self):
        self.entries = []

    def add(self, entry):
        self.entries.append(entry)

    def __str__(self):
        return "SegmentDefsRecord:" + "".join(["\n  " + str(e) for e in self.entries])
    
    
class SegmentDefsRecordEntry:
    def __init__(self, seg_id, seg_info, rel_type, seg_base, seg_size, seg_name):
        self.seg_id   = seg_id
        self.seg_info = SegInfo(seg_info)
        self.rel_type = rel_type
        self.seg_base = seg_base
        self.seg_size = seg_size
        self.seg_name = seg_name

    def __str__(self):
        return "seg_id:{seg_id}, seg_info:[{seg_info}], rel_type:{rel_type}, seg_base:{seg_base}, seg_size:{seg_size}, seg_name:{seg_name}".format(
            seg_id   = self.seg_id,
            seg_info = self.seg_info,
            rel_type = self.rel_type,
            seg_base = self.seg_base,
            seg_size = self.seg_size,
            seg_name = self.seg_name
            )
    

class PublicDefsRecord:
    def __init__(self):
        self.entries = []

    def add(self, entry):
        self.entries.append(entry)

    def __str__(self):
        return "PublicDefsRecord:" + "".join(["\n  " + str(e) for e in self.entries])

    def __iter__(self):
        return self.entries.__iter__()

    
class PublicDefsRecordEntry:
    def __init__(self, seg_id, sym_info, offset, public_name):
        self.seg_id      = seg_id
        self.sym_info    = SymInfo(sym_info)
        self.offset      = offset
        self.public_name = public_name

    def __str__(self):
        return "seg_id:{seg_id}, sym_info:[{sym_info}], offset:{offset}, public name:{public_name}".format(
            seg_id      = self.seg_id,
            sym_info    = self.sym_info,
            offset      = self.offset,
            public_name = self.public_name
        )

    
class ScopeDefRecord:
    def __init__(self, block_type, block_name):
        self.block_type = block_type
        self.block_name = block_name

    def __str__(self):
        return "ScopeDefRecord: block_type:{block_type}, block_name:{block_name}".format(
            block_type = self.block_type,
            block_name = self.block_name
            )

    
class DebugItemsRecordLocalSymbols:
    def __init__(self):
        self.entries = []

    def add(self, entry):
        self.entries.append(entry)

    def __str__(self):
        return "DebugItemsRecordLocalSymbols:" + "".join(["\n  " + str(e) for e in self.entries])

    def __iter__(self):
        return self.entries.__iter__()

    
class DebugItemsRecordLocalSymbolsEntry:
    def __init__(self, seg_id, sym_info, offset, sym_name):
        self.seg_id   = seg_id
        self.sym_info = SymInfo(sym_info)
        self.offset   = offset
        self.sym_name = sym_name

    def __str__(self):
        return "seg_id:{seg_id}, sym_info:[{sym_info}], offset:{offset}, sym_name:{sym_name}".format(
            seg_id   = self.seg_id,
            sym_info = self.sym_info,
            offset   = self.offset,
            sym_name = self.sym_name
            )
    

class DebugItemsRecordPublicSymbols:
    def __init__(self):
        self.entries = []

    def add(self, entry):
        self.entries.append(entry)

    def __str__(self):
        return "DebugItemsRecordPublicSymbols:" + "".join(["\n  " + str(e) for e in self.entries])
    
    def __iter__(self):
        return self.entries.__iter__()

    
class DebugItemsRecordPublicSymbolsEntry:
    def __init__(self, seg_id, sym_info, offset, sym_name):
        self.seg_id   = seg_id
        self.sym_info = SymInfo(sym_info)
        self.offset   = offset
        self.sym_name = sym_name

    def __str__(self):
        return "seg_id:{seg_id}, sym_info:[{sym_info}], offset:{offset}, sym_name:{sym_name}".format(
            seg_id   = self.seg_id,
            sym_info = self.sym_info,
            offset   = self.offset,
            sym_name = self.sym_name
            )

    
class ContentRecord:
    def __init__(self, seg_id, offset, data):
        self.seg_id = seg_id
        self.offset = offset
        self.data   = data

    def __str__(self):
        return "ContentRecord: seg_id:{seg_id}, offset:{offset}, data size:{data_size}, data:{data}".format(
            seg_id = self.seg_id,
            offset = self.offset,
            data_size = len(self.data),
            data   = self.data ## "".join(hex(byte) + " " for byte in self.data)
            )

    def get_seg_id(self):
        return self.seg_id

    def get_offset(self):
        return self.offset

    def __iter__(self):
        return self.data.__iter__()
    

class Records:
    def __init__(self):
        self.records = []

    def add(self, record):
        self.records.append(record)

    def __iter__(self):
        return self.records.__iter__()

    def __str__(self):
        return "".join(["\n" + str(r) for r in self.records])

        
class OmfDecomposer:
    def __init__(self, objfile):
        self._objfile = objfile

    def __call__(self):
        "Decompose the omf object file and return a collection of OMF records"
        with open(self._objfile, 'rb') as f:
            return self._process(f)

    def _process(self, f):
        records  = Records()
        while f:
            try:
                rec_type = Utils.read_byte(f)
            except ValueError:
                break
            
            ## print("rec_type", rec_type)
            if rec_type == 0x02:
                record = self._create_module_header_record(f)
            elif rec_type == 0x04:
                record = self._create_module_end_record(f)
            elif rec_type == 0x0e:
                record = self._create_segment_defs_record(f)
            elif rec_type == 0x16:
                record = self._create_public_defs_records(f)
            elif rec_type == 0x10:
                record = self._create_scope_def_record(f)
            elif rec_type == 0x12:
                record = self._create_debug_items_record(f)
            elif rec_type == 0x06:
                record = self._create_content_record(f)
            else:
                raise Error("Record type %s not supported" % record_type)

            records.add(record)
        return records

    def _create_module_header_record(self, f):
        record_length = Utils.read_word(f)
        module_name   = Utils.read_string(f)
        trn_id        = Utils.read_byte(f)
        unused        = Utils.read_byte(f)
        chk_sum       = Utils.read_byte(f)
        return ModuleHeaderRecord(module_name, trn_id)

    def _create_module_end_record(self, f):
        record_length = Utils.read_word(f)
        module_name   = Utils.read_string(f)
        res           = Utils.read_word(f)
        reg_mask      = Utils.read_byte(f)
        res2          = Utils.read_byte(f)
        chk_sum       = Utils.read_byte(f)
        return ModuleEndRecord(module_name, reg_mask)
    
    def _create_segment_defs_record(self, f):
        record_length = Utils.read_word(f)
        
        data = Utils.read_raw(f, record_length)
        stream = io.BytesIO(data[:-1])
        chk_sum = data[-1:]
        
        record = SegmentDefsRecord()
        while(stream):
            try:
                seg_id = Utils.read_byte(stream)
            except(ValueError):
                break;
            
            seg_info = Utils.read_byte(stream)
            rel_type = Utils.read_byte(stream)
            unused = Utils.read_byte(stream)
            seg_base = Utils.read_word(stream)
            seg_size = Utils.read_word(stream)
            seg_name = Utils.read_string(stream)

            record.add( SegmentDefsRecordEntry(seg_id, seg_info, rel_type, seg_base, seg_size, seg_name) )

        return record

    def _create_public_defs_records(self, f):
        record_length = Utils.read_word(f)
        
        data = Utils.read_raw(f, record_length)
        stream = io.BytesIO(data[:-1])
        chk_sum = data[-1:]
        
        record = PublicDefsRecord()
        while(stream):
            try:
                seg_id = Utils.read_byte(stream)
            except(ValueError):
                break;
            
            sym_info = Utils.read_byte(stream)
            offset   = Utils.read_word(stream)
            unused   = Utils.read_byte(stream)
            public_name = Utils.read_string(stream)
            
            record.add( PublicDefsRecordEntry(seg_id, sym_info, offset, public_name) )

        return record

    def _create_scope_def_record(self, f):
        record_length = Utils.read_word(f)
        block_type    = Utils.read_byte(f)
        block_name    = Utils.read_string(f)
        chk_sum       = Utils.read_byte(f)

        return ScopeDefRecord(block_type, block_name)

    def _create_debug_items_record(self, f):
        record_length = Utils.read_word(f)

        data = Utils.read_raw(f, record_length) 
        stream = io.BytesIO(data[:-1])
        chk_sum = data[-1:]

        
        def_type = Utils.read_byte(stream)        
        if def_type == 0:
            return self._create_debug_items_record_local_symbols(stream)
        elif def_type == 1:
            return self._create_debug_items_record_public_symbols(stream)
        else:
            raise Error("Debug items record %s not supported", def_type)

    def _create_debug_items_record_local_symbols(self, f):
        record = DebugItemsRecordLocalSymbols()
        
        while(f):
            try:
                seg_id = Utils.read_byte(f)
            except(ValueError):
                break;

            sym_info = Utils.read_byte(f)
            offset   = Utils.read_word(f)
            res      = Utils.read_byte(f)
            sym_name = Utils.read_string(f)

            record.add( DebugItemsRecordLocalSymbolsEntry(seg_id, sym_info, offset, sym_name) )

        return record

    def _create_debug_items_record_public_symbols(self, f):
        record = DebugItemsRecordPublicSymbols()

        while(f):
            try:
                seg_id = Utils.read_byte(f)
            except(ValueError):
                break;

            sym_info = Utils.read_byte(f)
            offset   = Utils.read_word(f)
            res      = Utils.read_byte(f)
            sym_name = Utils.read_string(f)

            record.add( DebugItemsRecordPublicSymbolsEntry(seg_id, sym_info, offset, sym_name) )

        return record

    def _create_content_record(self, f):
        record_length = Utils.read_word(f)

        data = Utils.read_raw(f, record_length) 
        stream = io.BytesIO(data[:-1])
        chk_sum = data[-1:]
        
        seg_id = Utils.read_byte(stream)
        offset = Utils.read_word(stream)

        data = Utils.read_all(stream)

        return ContentRecord(seg_id, offset, data)


class Symbols:
    def __init__(self):
        self.symbols = []

    def add(self, symbol):
        if type(symbol) == Symbols:
            for s in symbol: self.add(s)
        else:
            self.symbols.append(symbol)

    def __str__(self):
        return "Symbols:" + "".join(["\n  " + str(s) for s in self.symbols])

    def __iter__(self):
        return self.symbols.__iter__()

    def __len__(self):
        return self.symbols.__len__()

    def sort(self):
        self.symbols.sort(key = lambda symbol: (symbol.get_type() << 32) + symbol.get_offset())

    def split_by_seg_id(self):
        "Returns a dictionary with (key,value) = (seg_id,Symbols)"

        result = defaultdict(Symbols)
        for symbol in self.symbols:
            result[symbol.get_seg_id()].add( symbol )

        return result

    def find_code_symbol_by_offset(self, offset):
        for symbol in self.symbols:
            if symbol.is_code() and symbol.get_offset() == offset:
                return symbol
        return None

    def find_non_code_symbol_by_offset(self, offset):
        for symbol in self.symbols:
            if (not symbol.is_code())  and  (symbol.get_offset() == offset):
                return symbol
        return None
    
    def get_subset(self, condition):
        """Return subset containing all symbols which fulfill the given condition
        The condition has the syntax: condition(symbol)
        """        
        result = Symbols()
        for symbol in self.symbols:
            if condition(symbol):
                result.add( symbol )
        return result

        
class Symbol:
    def __init__(self, seg_id, sym_info, offset, name):
        self.seg_id = seg_id
        self.sym_info = sym_info
        self.offset = offset
        self.name = name

    def __str__(self):
        return "seg_id:{seg_id}, sym_info:[{sym_info}], offset:{offset}, name:{name}".format(
            seg_id   = self.seg_id,
            sym_info = self.sym_info,
            offset   = self.offset,
            name = self.name
            )

    def get_offset(self):
        return self.offset
    
    def get_type(self):
        return self.sym_info.usage_type.get_type()

    def get_seg_id(self):
        return self.seg_id;

    def get_name(self):
        return self.name

    def is_code(self):
        "Returns true if this symbol is of type CODE"
        return self.sym_info.is_code()

    def is_xdata(self):
        return self.sym_info.is_xdata()

    def is_data(self):
        return self.sym_info.is_data()

    def is_idata(self):
        return self.sym_info.is_idata()

    def is_bit(self):
        return self.sym_info.is_bit()

    def is_number(self):
        return self.sym_info.is_number()

class CodeBlocks:
    def __init__(self):
        self.blocks = []

    def add(self, code_block):
        self.blocks.append(code_block)

    def __iter__(self):
        return self.blocks.__iter__()

    def __str__(self):
        return "CodeBlocks:" + "".join(["\n  " + str(s) for s in self.blocks])

    def split_by_seg_id(self):
        "Returns a dictionary with (key,value) = (seg_id,CodeBlocks)"

        result = defaultdict(CodeBlocks)
        for code_block in self.blocks:
            result[code_block.get_seg_id()].add( code_block )
            
        return result

    
class Segment:
    def __init__(self, seg_id, code_blocks, symbols):
        self.seg_id      = seg_id
        self.code_blocks = code_blocks
        self.symbols     = symbols

    def __str__(self):
        return "Segment: seg_id:{seg_id}\n{symbols}\n{code_blocks}".format(
            seg_id = self.seg_id,
            symbols = str(self.symbols),
            code_blocks = str(self.code_blocks)
            )

    def get_code_blocks(self):
        return self.code_blocks

    
class Disassembler:
    def __init__(self, omf_records):
        self.records = omf_records

    def __call__(self):
        ## First get all symbol informations:
        symbols = self._create_symbols()
        symbols.sort()

        ## get all code 
        code_blocks = self._create_code_blocks()

        ## Split code_blocks and symbols container by seg id
        seg_list = self._create_seg_list(code_blocks, symbols)
        for segment in seg_list:
            seg_disassembler = SegDisassembler(segment)
            seg_disassembler()
                
    def _create_symbols(self):
        symbols = Symbols()
        for record in self.records:
            symbol = self._create_symbols_from_record(record)
            symbols.add( symbol )
        return symbols

    def _create_symbols_from_record(self, record):
        symbols = Symbols()
        if type(record) == PublicDefsRecord:
            for r in record:
                symbols.add( Symbol(r.seg_id, r.sym_info, r.offset, r.public_name) )
                
        elif (type(record) == DebugItemsRecordLocalSymbols) or \
             (type(record) == DebugItemsRecordPublicSymbols):
            for r in record:
                symbols.add( Symbol(r.seg_id, r.sym_info, r.offset, r.sym_name) )
                
        return symbols

    def _create_code_blocks(self):
        code_blocks = CodeBlocks()
        for record in self.records:
            if type(record) == ContentRecord:
                code_blocks.add(record)
        return code_blocks

    def _create_seg_list(self, code_blocks, symbols):
        seg_symbols_dict     = symbols    .split_by_seg_id()
        seg_code_blocks_dict = code_blocks.split_by_seg_id()

        seg_list = []
        for seg_id, code_blocks in seg_code_blocks_dict.items():
            seg_list.append( Segment(seg_id,
                                     code_blocks,
                                     seg_symbols_dict[seg_id]) )
            
        return seg_list
            
    
class SegDisassembler:
    def __init__(self, segment):
        self.segment = segment

    def __call__(self):
        self._show_symbols("XDATA", lambda symbol: symbol.is_xdata())
        self._show_symbols("DATA",  lambda symbol: symbol.is_data())
        self._show_symbols("IDATA",  lambda symbol: symbol.is_idata())
        self._show_symbols("BIT",  lambda symbol: symbol.is_bit())
        self._show_symbols("NUMBER",  lambda symbol: symbol.is_number())
        self._show_raw_code()

        functions = self._create_functions()
        for f in functions:
            fd = FunctionDisassbler(f, self.segment.symbols)
            fd()
        print(functions)
        
    def _show_symbols(self, identifier, condition):
        print("%s:" % identifier)
        symbols = self.segment.symbols.get_subset(condition)
        if not symbols:
            return
        symbols.sort()

        offset = 0
        for symbol in symbols:
            if offset == 0:
                offset = symbol.get_offset()
            while(offset < symbol.get_offset()):
                print(" {offset:>5}:".format(offset=offset))
                offset += 1

            print(" {offset:>5}:\t{name}\t".format(offset=symbol.get_offset(), name=symbol.get_name()))
        
    def _show_raw_code(self):
        for code_block in self.segment.get_code_blocks():
            offset = code_block.get_offset()
            print("\nCODE BLOCK: offset=%s" % offset)
            for byte in code_block:
                symbol = self.segment.symbols.find_code_symbol_by_offset(offset=offset)
                if symbol:
                    print(" %s:" % symbol.get_name())
                print("    {offset:>5}:\t{byte:x}".format(offset=offset, byte=byte))
                offset += 1

    def _create_functions(self):
        functions = Functions()

        func = None
        offset = -1
        for code_block in self.segment.get_code_blocks():
            if offset != code_block.get_offset():
                if func:
                    functions.add(func)                    
                func = Function("<unnamed>")
                
            offset = code_block.get_offset()
            for byte in code_block:
                symbol = self.segment.symbols.find_code_symbol_by_offset(offset=offset)
                if symbol:
                    ## If at this address we have a symbol, than here a new
                    ## function is starting
                    functions.add(func)
                    func = Function(symbol.get_name())

                func.add(offset, byte)
                offset += 1

        return functions                


class FunctionElement:
    def __init__(self, offset, byte):
        self.offset = offset
        self.byte   = byte
    

class Function:
    def __init__(self, name):
        self.name = name
        self.elements = []
        self.instructions = None
        
    def add(self, offset, byte):
        self.elements.append( FunctionElement(offset, byte) )

    def __str__(self):
        return \
            "Function: %s" % self.name + \
            "".join(["\n    {offset:>5}:\t{byte:x}".format(offset=e.offset, byte=e.byte) for e in self.elements]) + \
            "\nFunction(DISASM): %s\n" % self.name + \
            str(self.instructions)

    def __iter__(self):
        return self.elements.__iter__()
    

class Functions:
    def __init__(self):
        self.functions = []
        
    def add(self, function):
        self.functions.append( function )

    def __str__(self):
        return "FUNCTIONS:" + "".join(["\n" + str(f) for f in self.functions])

    def __iter__(self):
        return self.functions.__iter__()

    
class FunctionDisassbler:
    def __init__(self, function, symbols):
        self.function = function
        self.symbols  = symbols
    
    def __call__(self):
        self._validate_function_elements_are_continious()
        self.function.instructions = self._disassemble()
        
    def _validate_function_elements_are_continious(self):
        offset_last = None
        is_first = True
        for element in self.function:
            if is_first:
                is_first = False
                offset_last = element.offset
            else:
                if offset_last + 1 != element.offset:
                    raise Error("Function: %s contains non-continous elements" % self.function.name)
                
            offset_last = element.offset

    def _disassemble(self):
        instructions = Instructions()    
        ie = InstructionCreator(self.symbols)
        offset = -1
        for element in self.function:
            if offset == -1:
                offset = element.offset
                
            ie.add_byte(element.byte)
            instruction = ie.create()
            if instruction:
                instruction.offset = offset
                offset = -1
                
                instructions.add( instruction )
                
        return instructions

class Instructions:
    def __init__(self):
        self.instructions = []

    def add(self, instruction):
        self.instructions.append( instruction )

    def __len__(self):
        return self.instructions.__len__()

    def __str__(self):
        return "".join(["   {i}\n".format(i=instruction) for instruction in self.instructions])

                       
class Instruction:
    def __init__(self, op):
        self.offset = None
        self.op = op

    def __str__(self):
        return "{offset}:\t{op}".format(offset=self.offset, op=self.op)

        
class InstructionCreator:
    def __init__(self, symbols):
        self.symbols = symbols
        self.instructions = []
        self.parts = []
        self.byte0 = None
        self.it    = None
        
        self.op_table = {
            0x00: lambda: self._x                    ("NOP"),
            0x01: lambda: self._x_addr11             ("AJMP"),
            0x02: lambda: self._x_addr16             ("LJMP"),
            0x03: lambda: self._x_a                  ("RR"),
            0x04: lambda: self._x_a                  ("INC"),
            0x05: lambda: self._x_direct             ("INC"),
            0x06: lambda: self._x_at_ri              ("INC", 0),
            0x07: lambda: self._x_at_ri              ("INC", 1),
            0x08: lambda: self._x_ri                 ("INC", 0),
            0x09: lambda: self._x_ri                 ("INC", 1),
            0x0a: lambda: self._x_ri                 ("INC", 2),
            0x0b: lambda: self._x_ri                 ("INC", 3),
            0x0c: lambda: self._x_ri                 ("INC", 4),
            0x0d: lambda: self._x_ri                 ("INC", 5),
            0x0e: lambda: self._x_ri                 ("INC", 6),
            0x0f: lambda: self._x_ri                 ("INC", 7),
            
            0x10: lambda: self._x_bit_offset         ("JBC"),
            0x11: lambda: self._x_addr11             ("ACALL"),
            0x12: lambda: self._x_addr16             ("LCALL"),
            0x13: lambda: self._x_a                  ("RRC"),
            0x14: lambda: self._x_a                  ("DEC"),
            0x15: lambda: self._x_direct             ("DEC"),
            0x16: lambda: self._x_at_ri              ("DEC", 0),
            0x17: lambda: self._x_at_ri              ("DEC", 1),
            0x18: lambda: self._x_ri                 ("DEC", 0),
            0x19: lambda: self._x_ri                 ("DEC", 1),
            0x1a: lambda: self._x_ri                 ("DEC", 2),
            0x1b: lambda: self._x_ri                 ("DEC", 3),
            0x1c: lambda: self._x_ri                 ("DEC", 4),
            0x1d: lambda: self._x_ri                 ("DEC", 5),
            0x1e: lambda: self._x_ri                 ("DEC", 6),
            0x1f: lambda: self._x_ri                 ("DEC", 7),
            
            0x20: lambda: self._x_bit_offset         ("JB"),
            0x21: lambda: self._x_addr11             ("AJMP"),
            0x22: lambda: self._x                    ("RET"),
            0x23: lambda: self._x_a                  ("RL"),
            0x24: lambda: self._x_a_immed            ("ADD"),
            0x25: lambda: self._x_a_direct           ("ADD"),
            0x26: lambda: self._x_a_at_ri            ("ADD", 0),
            0x27: lambda: self._x_a_at_ri            ("ADD", 1),
            0x28: lambda: self._x_a_ri               ("ADD", 0),
            0x29: lambda: self._x_a_ri               ("ADD", 1),
            0x2a: lambda: self._x_a_ri               ("ADD", 2),
            0x2b: lambda: self._x_a_ri               ("ADD", 3),
            0x2c: lambda: self._x_a_ri               ("ADD", 4),
            0x2d: lambda: self._x_a_ri               ("ADD", 5),
            0x2e: lambda: self._x_a_ri               ("ADD", 6),
            0x2f: lambda: self._x_a_ri               ("ADD", 7),

            0x30: lambda: self._x_bit_offset         ("JNB"),
            0x31: lambda: self._x_addr               ("ACALL"),
            0x32: lambda: self._x                    ("RETI"),
            0x33: lambda: self._x_a                  ("RLC"),
            0x34: lambda: self._x_a_immed            ("ADDC"),
            0x35: lambda: self._x_a_direc            ("ADDC"),
            0x36: lambda: self._x_a_at_ri            ("ADDC", 0),
            0x37: lambda: self._x_a_at_ri            ("ADDC", 1),
            0x38: lambda: self._x_a_ri               ("ADDC", 0),
            0x39: lambda: self._x_a_ri               ("ADDC", 1),
            0x3a: lambda: self._x_a_ri               ("ADDC", 2),
            0x3b: lambda: self._x_a_ri               ("ADDC", 3),
            0x3c: lambda: self._x_a_ri               ("ADDC", 4),
            0x3d: lambda: self._x_a_ri               ("ADDC", 5),
            0x3e: lambda: self._x_a_ri               ("ADDC", 6),
            0x3f: lambda: self._x_a_ri               ("ADDC", 7),

            0x40: lambda: self._x_offset             ("JC"),
            0x41: lambda: self._x_addr11             ("AJMP"),
            0x42: lambda: self._x_direct_a           ("ORL"),
            0x43: lambda: self._x_direct_immed       ("ORL"),
            0x44: lambda: self._x_a_immed            ("ORL"),
            0x45: lambda: self._x_a_direct           ("ORL"),
            0x46: lambda: self._x_a_at_ri            ("ORL", 0),
            0x47: lambda: self._x_a_at_ri            ("ORL", 1),
            0x48: lambda: self._x_a_ri               ("ORL", 0),
            0x49: lambda: self._x_a_ri               ("ORL", 1),
            0x4a: lambda: self._x_a_ri               ("ORL", 2),
            0x4b: lambda: self._x_a_ri               ("ORL", 3),
            0x4c: lambda: self._x_a_ri               ("ORL", 4),
            0x4d: lambda: self._x_a_ri               ("ORL", 5),
            0x4e: lambda: self._x_a_ri               ("ORL", 6),
            0x4f: lambda: self._x_a_ri               ("ORL", 7),

            0x50: lambda: self._x_offset             ("JNC"),
            0x51: lambda: self._x_addr11             ("ACALL"),
            0x52: lambda: self._x_direct_a           ("ANL"),
            0x53: lambda: self._x_direct_immed       ("ANL"),
            0x54: lambda: self._x_a_immed            ("ANL"),
            0x55: lambda: self._x_a_direct           ("ANL"),
            0x56: lambda: self._x_a_at_ri            ("ANL", 0),
            0x57: lambda: self._x_a_at_ri            ("ANL", 1),
            0x58: lambda: self._x_a_ri               ("ANL", 0),
            0x59: lambda: self._x_a_ri               ("ANL", 1),
            0x5a: lambda: self._x_a_ri               ("ANL", 2),
            0x5b: lambda: self._x_a_ri               ("ANL", 3),
            0x5c: lambda: self._x_a_ri               ("ANL", 4),
            0x5d: lambda: self._x_a_ri               ("ANL", 5),
            0x5e: lambda: self._x_a_ri               ("ANL", 6),
            0x5f: lambda: self._x_a_ri               ("ANL", 7),

            0x60: lambda: self._x_offset             ("JZ"),
            0x61: lambda: self._x_addr11             ("AJMP"),
            0x62: lambda: self._x_direct_a           ("XRL"),
            0x63: lambda: self._x_direct_immed       ("XRL"),
            0x64: lambda: self._x_a_immed            ("XRL"),
            0x65: lambda: self._x_a_direct           ("XRL"),
            0x66: lambda: self._x_a_at_ri            ("XRL", 0),
            0x67: lambda: self._x_a_at_ri            ("XRL", 1),
            0x68: lambda: self._x_a_ri               ("XRL", 0),
            0x69: lambda: self._x_a_ri               ("XRL", 1),
            0x6a: lambda: self._x_a_ri               ("XRL", 2),
            0x6b: lambda: self._x_a_ri               ("XRL", 3),
            0x6c: lambda: self._x_a_ri               ("XRL", 4),
            0x6d: lambda: self._x_a_ri               ("XRL", 5),
            0x6e: lambda: self._x_a_ri               ("XRL", 6),
            0x6f: lambda: self._x_a_ri               ("XRL", 7),

            0x70: lambda: self._x_offset             ("JNZ"), 
            0x71: lambda: self._x_addr11             ("ACALL"),
            0x72: lambda: self._x_c_bit              ("ORL"),
            0x73: lambda: self._x_at_a_dptr          ("JMP"),
            0x74: lambda: self._x_a_immed            ("MOV"),
            0x75: lambda: self._x_direct_immed       ("MOV"),
            0x76: lambda: self._x_at_ri_immed        ("MOV", 0),
            0x77: lambda: self._x_at_ri_immed        ("MOV", 1),
            0x78: lambda: self._x_ri_immed           ("MOV", 0),
            0x79: lambda: self._x_ri_immed           ("MOV", 1),
            0x7a: lambda: self._x_ri_immed           ("MOV", 2),
            0x7b: lambda: self._x_ri_immed           ("MOV", 3),
            0x7c: lambda: self._x_ri_immed           ("MOV", 4),
            0x7d: lambda: self._x_ri_immed           ("MOV", 5),
            0x7e: lambda: self._x_ri_immed           ("MOV", 6),
            0x7f: lambda: self._x_ri_immed           ("MOV", 7),

            0x80: lambda: self._x_offset             ("SJMP"),
            0x81: lambda: self._x_addr11             ("AJMP"),
            0x82: lambda: self._x_c_bit              ("ANL"),
            0x83: lambda: self._x_a_at_a_plus_pc     ("MOVC"),
            0x84: lambda: self._x_ab                 ("DIV"),
            0x85: lambda: self._x_direct_direct      ("MOV"),
            0x86: lambda: self._x_direct_at_ri       ("MOV", 0),
            0x87: lambda: self._x_direct_at_ri       ("MOV", 1),
            0x88: lambda: self._x_direct_ri          ("MOV", 0),
            0x89: lambda: self._x_direct_ri          ("MOV", 1),
            0x8a: lambda: self._x_direct_ri          ("MOV", 2),
            0x8b: lambda: self._x_direct_ri          ("MOV", 3),
            0x8c: lambda: self._x_direct_ri          ("MOV", 4),
            0x8d: lambda: self._x_direct_ri          ("MOV", 5),
            0x8e: lambda: self._x_direct_ri          ("MOV", 6),
            0x8f: lambda: self._x_direct_ri          ("MOV", 7),

            0x90: lambda: self._x_dptr_immed         ("MOV"),
            0x91: lambda: self._x_addr11             ("ACALL"),
            0x92: lambda: self._x_bit_c              ("MOV"),
            0x93: lambda: self._x_a_at_a_dptr        ("MOVC"),
            0x94: lambda: self._x_a_immed            ("SUBB"),
            0x95: lambda: self._x_a_direct           ("SUBB"),
            0x96: lambda: self._x_a_at_ri            ("SUBB", 0),
            0x97: lambda: self._x_a_at_ri            ("SUBB", 1),
            0x98: lambda: self._x_a_ri               ("SUBB", 0),
            0x99: lambda: self._x_a_ri               ("SUBB", 1),
            0x9a: lambda: self._x_a_ri               ("SUBB", 2),
            0x9b: lambda: self._x_a_ri               ("SUBB", 3),
            0x9c: lambda: self._x_a_ri               ("SUBB", 4),
            0x9d: lambda: self._x_a_ri               ("SUBB", 5),
            0x9e: lambda: self._x_a_ri               ("SUBB", 6),
            0x9f: lambda: self._x_a_ri               ("SUBB", 7),

            0xa0: lambda: self._x_c_not_bit          ("ORL"),
            0xa1: lambda: self._x_addr11             ("AJMP"),
            0xa2: lambda: self._x_c_bit              ("MOV"),
            0xa3: lambda: self._x_dptr               ("INC"),
            0xa4: lambda: self._x_ab                 ("MUL"),
            0xa5: lambda: None,
            0xa6: lambda: self._x_at_ri_direct       ("MOV", 0),
            0xa7: lambda: self._x_at_ri_direct       ("MOV", 1),
            0xa8: lambda: self._x_ri_direct          ("MOV", 0),
            0xa9: lambda: self._x_ri_direct          ("MOV", 1),
            0xaa: lambda: self._x_ri_direct          ("MOV", 2),
            0xab: lambda: self._x_ri_direct          ("MOV", 3),
            0xac: lambda: self._x_ri_direct          ("MOV", 4),
            0xad: lambda: self._x_ri_direct          ("MOV", 5),
            0xae: lambda: self._x_ri_direct          ("MOV", 6),
            0xaf: lambda: self._x_ri_direct          ("MOV", 7),

            0xb0: lambda: self._x_c_not_bit          ("ANL"),
            0xb1: lambda: self._x_addr11             ("ACALL"),
            0xb2: lambda: self._x_bit                ("CPL"),
            0xb3: lambda: self._x_c                  ("CPL"),
            0xb4: lambda: self._x_a_immed_offset     ("CJNE"),
            0xb5: lambda: self._x_a_direct_offset    ("CJNE"),
            0xb6: lambda: self._x_at_ri_immed_offset ("CJNE", 0),
            0xb7: lambda: self._x_at_ri_immed_offset ("CJNE", 1),
            0xb8: lambda: self._x_ri_immed_offset    ("CJNE", 0),
            0xb9: lambda: self._x_ri_immed_offset    ("CJNE", 1),
            0xba: lambda: self._x_ri_immed_offset    ("CJNE", 2),
            0xbb: lambda: self._x_ri_immed_offset    ("CJNE", 3),
            0xbc: lambda: self._x_ri_immed_offset    ("CJNE", 4),
            0xbd: lambda: self._x_ri_immed_offset    ("CJNE", 5),
            0xbe: lambda: self._x_ri_immed_offset    ("CJNE", 6),
            0xbf: lambda: self._x_ri_immed_offset    ("CJNE", 7),

            0xc0: lambda: self._x_direct             ("PUSH"),
            0xc1: lambda: self._x_addr               ("AJMP"),
            0xc2: lambda: self._x_bit                ("CLR"),
            0xc3: lambda: self._x_c                  ("CLR"),
            0xc4: lambda: self._x_a                  ("SWAP"),
            0xc5: lambda: self._x_a_direct           ("XCH"),
            0xc6: lambda: self._x_a_at_ri            ("XCH", 0),
            0xc7: lambda: self._x_a_at_ri            ("XCH", 1),
            0xc8: lambda: self._x_a_ri               ("XCH", 0),
            0xc9: lambda: self._x_a_ri               ("XCH", 1),
            0xca: lambda: self._x_a_ri               ("XCH", 2),
            0xcb: lambda: self._x_a_ri               ("XCH", 3),
            0xcc: lambda: self._x_a_ri               ("XCH", 4),
            0xcd: lambda: self._x_a_ri               ("XCH", 5),
            0xce: lambda: self._x_a_ri               ("XCH", 6),
            0xcf: lambda: self._x_a_ri               ("XCH", 7),

            0xd0: lambda: self._x_direct             ("POP"),
            0xd1: lambda: self._x_addr11             ("ACALL"),
            0xd2: lambda: self._x_bit                ("SETB"),
            0xd3: lambda: self._x_c                  ("SETB"),
            0xd4: lambda: self._x_a                  ("DA"),
            0xd5: lambda: self._x_direct_offset      ("DJNZ"),
            0xd6: lambda: self._x_a_at_ri            ("XCHD", 0),
            0xd7: lambda: self._x_a_at_r1            ("XCHD", 1),
            0xd8: lambda: self._x_ri_offset          ("DJNZ", 0),
            0xd9: lambda: self._x_ri_offset          ("DJNZ", 1),
            0xda: lambda: self._x_ri_offset          ("DJNZ", 2),
            0xdb: lambda: self._x_ri_offset          ("DJNZ", 3),
            0xdc: lambda: self._x_ri_offset          ("DJNZ", 4),
            0xdd: lambda: self._x_ri_offset          ("DJNZ", 5),
            0xde: lambda: self._x_ri_offset          ("DJNZ", 6),
            0xdf: lambda: self._x_ri_offset          ("DJNZ", 7),

            0xe0: lambda: self._x_a_at_dptr          ("MOVX"),
            0xe1: lambda: self._x_addr11             ("AJMP"),
            0xe2: lambda: self._x_a_at_ri            ("MOVX", 0),
            0xe3: lambda: self._x_a_at_ri            ("MOVX", 1),
            0xe4: lambda: self._x_a                  ("CLR"),
            0xe5: lambda: self._x_a_direct           ("MOV"),
            0xe6: lambda: self._x_a_at_ri            ("MOV", 0),
            0xe7: lambda: self._x_a_at_ri            ("MOV", 1),
            0xe8: lambda: self._x_a_ri               ("MOV", 0),
            0xe9: lambda: self._x_a_ri               ("MOV", 1),
            0xea: lambda: self._x_a_ri               ("MOV", 2),
            0xeb: lambda: self._x_a_ri               ("MOV", 3),
            0xec: lambda: self._x_a_ri               ("MOV", 4),
            0xed: lambda: self._x_a_ri               ("MOV", 5),
            0xee: lambda: self._x_a_ri               ("MOV", 6),
            0xef: lambda: self._x_a_ri               ("MOV", 7),

            0xf0: lambda: self._x_at_dptr_a          ("MOVX"),
            0xf1: lambda: self._x_addr11             ("ACALL"),
            0xf2: lambda: self._x_at_ri_a            ("MOVX", 0),
            0xf3: lambda: self._x_at_ri_a            ("MOVX", 1),
            0xf4: lambda: self._x_a                  ("CPL"),
            0xf5: lambda: self._x_direct_a           ("MOV"),
            0xf6: lambda: self._x_at_ri_a            ("MOV", 0),
            0xf7: lambda: self._x_at_ri_a            ("MOV", 1),
            0xf8: lambda: self._x_ri_a               ("MOV", 0),
            0xf9: lambda: self._x_ri_a               ("MOV", 1),
            0xfa: lambda: self._x_ri_a               ("MOV", 2),
            0xfb: lambda: self._x_ri_a               ("MOV", 3),
            0xfc: lambda: self._x_ri_a               ("MOV", 4),
            0xfd: lambda: self._x_ri_a               ("MOV", 5),
            0xfe: lambda: self._x_ri_a               ("MOV", 6),
            0xff: lambda: self._x_ri_a               ("MOV", 7)            
            }
        
    def add_byte(self, byte):
        self.parts.append(byte)

    class InvalidInstruction(Error):
        def __init__(self, instruction):
            Error.__init__(self, "Invalid %s instruction" % instruction)
    
    def create(self):
        """Create and return instruction

        In case the instruction is not yet completed because too less bytes are 
        added None is returned. 

        In case the bytes do not create a valid instruction an exception is 
        thrown.
        """
        if not self.parts:
            return None

        self.it    = iter(self.parts)
        self.byte0 = next(self.it)

        try:
            f = self.op_table[self.byte0]
        except KeyError:
            raise Error("Instruction %#x not found" % self.byte0)

        instruction = f()
        if instruction:
            self.parts.clear()

        return instruction
        
        
    def _x(self, op):
        if len(self.parts) != 1: raise self.InvalidInstruction(op)
        return Instruction(op)            

    def _x_a(self, op):
        if len(self.parts) != 1: raise self.InvalidInstruction("%s A" % op)
        return Instruction("%s A" % op)
    
    def _x_offset(self, op):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: raise self.InvalidInstruction("%s offset" % op)
        byte1 = next(self.it)
        offset = self.to_offset(byte1)
        return Instruction("%s offset=%s" % (op, offset))
        
    def _x_addr11(self, op):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: raise self.InvalidInstruction("%s addr11" % op)            
        byte1 = next(self.it)
        addr11 = self._get_addr11(self.byte0, byte1)
        return Instruction("%s %s" % (op, self._get_function_name(addr11)))

    def _x_addr16(self, op):
        if   len(self.parts)  < 3: return None
        elif len(self.parts) != 3: self.InvalidInstruction("%s addr16" % op)
        byte1 = next(self.it)
        byte2 = next(self.it)
        addr16 = self._get_addr16(byte1, byte2)
        return Instruction("%s %s" % (op, self._get_function_name(addr16)))

    def _x_bit(self, op):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: raise self.InvalidInstruction("%s bit" % op)            
        byte1 = next(self.it)
        return Instruction("%s (Bit:%s)" % (op, self._get_symbol(byte1)))
        
    def _x_at_ri(self, op, i):
        if len(self.parts) != 1: self.InvalidInstruction("%s @Ri" % op)
        return Instruction("%s @R%s" % (op, i))            

    def _x_at_ri_a(self, op, i):
        if len(self.parts) != 1: self.InvalidInstruction("%s @Ri, A" % op)
        return Instruction("%s @R%s, A" % (op, i))            
    
    def _x_ri(self, op, i):
        if len(self.parts) != 1: self.InvalidInstruction("%s Ri" % op)
        return Instruction("%s R%s" % (op, i))

    def _x_ri_a(self, op, i):
        if len(self.parts) != 1: self.InvalidInstruction("%s Ri, A" % op)
        return Instruction("%s R%s, A" % (op, i))
    
    def _x_ri_immed(self, op, i):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s Ri, #immed" % op)
        byte1 = next(self.it)
        return Instruction("%s R%s, #%s" % (op, i, byte1))

    def _x_ri_direct(self, op, i):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s Ri, direct" % op)
        byte1 = next(self.it)
        return Instruction("%s R%s, (%s)" % (op, i, self._get_symbol(byte1)))

    def _x_ri_offset(self, op, i):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s Ri, offset" % op)
        byte1 = next(self.it)
        offset = self.to_offset(byte1)
        return Instruction("%s R%s, offset=%s" % (op, i, offset))
    
    def _x_a_immed(self, op):
        if   len(self.parts)  < 2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s A, #immed" % op)
        byte1 = next(self.it)
        return Instruction("%s A, #%s" % (op, byte1))

    def _x_a_immed_offset(self, op):
        if   len(self.parts)  < 3: return None
        elif len(self.parts) != 3: self.InvalidInstruction("%s A, #immed, offset" % op)
        byte1 = next(self.it)
        byte2 = next(self.it)
        offset = self.to_offset(byte2)
        return Instruction("%s A, #%s, offset=%s" % (op, byte1, offset))
    
    def _x_a_direct(self, op):
        if   len(self.parts)  < 2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s A, direct" % op)
        byte1 = next(self.it)
        return Instruction("%s A, (%s)" % (op, self._get_symbol(byte1)))    

    def _x_a_at_dptr(self, op):
        if len(self.parts) != 1: self.InvalidInstruction("%s A, @DPTR" % op)
        return Instruction("%s A, @DPTR" % op)

    def _x_direct(self, op):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s direct" %s)
        byte1 = next(self.it)
        return Instruction("%s (%s)" % (op, self._get_symbol(byte1)))

    def _x_direct_direct(self, op):
        if   len(self.parts) <  3: return None
        elif len(self.parts) != 3: self.InvalidInstruction("%s direct, direct" %s)
        byte1 = next(self.it)
        byte2 = next(self.it)
        return Instruction("%s (src:%s), (dst:%s)" % (op, self._get_symbol(byte1), self._get_symbol(byte2)))

    def _x_direct_a(self, op):
        if   len(self.parts) <  2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s direct, A" %s)
        byte1 = next(self.it)
        return Instruction("%s (%s), A" % (op, self._get_symbol(byte1)))                               

    def _x_direct_offset(self, op):
        if   len(self.parts) <  3: return None
        elif len(self.parts) != 3: self.InvalidInstruction("%s direct, offset" %s)
        byte1 = next(self.it)
        byte2 = next(self.it)
        offset = self.to_offset(byte2)
        return Instruction("%s (%s), offset=%s" % (op, self._get_symbol(byte1), offset))
    
    def _x_direct_immed(self, op):
        if   len(self.parts)  < 3: return None
        elif len(self.parts) != 3: self.InvalidInstruction("%s direct, #immed" % op)
        byte1 = next(self.it)
        byte2 = next(self.it)
        return Instruction("%s (%s), #%s" % (op, self._get_symbol(byte1), byte2))

    def _x_a_at_ri(self, op, i):
        if len(self.parts) != 1: self.InvalidInstruction("%s A, @Ri" % op)
        return Instruction("%s A, @R%s" % (op, i))

    def _x_a_ri(self, op, i):
        if len(self.parts) != 1: self.InvalidInstruction("%s A, Ri" % op)
        return Instruction("%s A, R%s" % (op, i))

    def _x_a_direct_offset(self, op):
        if   len(self.parts)  < 3: return None
        elif len(self.parts) != 3: self.InvalidInstruction("%s A, direct, offset" % op)
        byte1 = next(self.it)
        byte2 = next(self.it)
        offset = self.to_offset(byte2)
        return Instruction("%s A, (%s), offset=%s" % (op, self._get_symbol(byte1), offset))
    
    def _x_a_at_a_plus_pc(self, op):
        if len(self.parts) != 1: self.InvalidInstruction("%s A, @A+PC" % op)
        return Instruction("%s A, @A+PC" % op)

    def _x_bit_c(self, op):
        if   len(self.parts)  < 2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s bic, C" % op)
        byte1 = next(self.it)
        return Instruction("%s (Bit:%s), C" % (op, self._get_symbol(byte1)))
        
    def _x_bit_offset(self, op):
        if   len(self.parts) <  3: return None
        elif len(self.parts) != 3: self.InvalidInstruction("%s bit,offset" % op)
        byte1 = next(self.it)
        byte2 = next(self.it)
        offset = self.to_offset(byte2)
        return Instruction("%s bit=%s, offset=%s" % (op, self._get_symbol(byte1), offset))

    def _x_c(self, op):
        if len(self.parts) != 1: self.InvalidInstruction("%s C" % op)
        return Instruction("%s C" % op)
                
    def _x_c_bit(self, op):
        if   len(self.parts)  < 2: return None
        elif len(self.parts) != 2: self.InvalidInstruction("%s C, bit" % op)
        byte1 = next(self.it)
        return Instruction("%s C, (Bit:%s)" % (op, self._get_symbol(byte1)))

    def _x_dptr(self, op):
        if len(self.parts) != 1: self.InvalidInstruction("%s DPTR" % op)
        return Instruction("%s DPTR" % op)
    
    def _x_at_dptr_a(self, op):
        if len(self.parts) != 1: self.InvalidInstruction("%s @DPTR, A" % op)
        return Instruction("%s @DPTR, A" % op)

    def _x_ab(self, op):
        if len(self.parts) != 1: self.InvalidInstruction("%s AB" % op)
        return Instruction("%s AB" % op)
        
        
    def _get_addr11(self, byte0, byte1):
        return ((byte0 & 0xe0) << 8) + byte1

    def _get_addr16(self, byte1, byte2):
        return (byte1 << 8) + byte2
    
    def _get_symbol(self, offset):
        symbol = self.symbols.find_non_code_symbol_by_offset(offset)
        if symbol: return symbol.get_name()
        else: return offset

    def _get_function_name(self, offset):
        symbol = self.symbols.find_code_symbol_by_offset(offset)
        if symbol: return symbol.get_name()
        else: return offset

    def to_offset(self, value):
        # Offsets are singed integers, s.t. one can jump foward and backwards.
        # Also it is expected here tha value has size of 1 byte!
        if value > 127: return -256 + value;
        else:           return value
        
                
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Disassembler for 8051/OMF")
    parser.add_argument('-f', '--file', required=True, help="The 8051 object file")
    args = parser.parse_args()

    omf_decomposer = OmfDecomposer(args.file)
    omf_records = omf_decomposer()
    #print(omf_records)

    disassembler = Disassembler(omf_records)
    disassembler()
