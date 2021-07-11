type Int64 = string;

type Endian = 'be' | 'le';

interface Instruction {
  address: string;
  mnemonic: string;
  opStr: string;
  groups: string[];
}

type ArmOperand = ArmRegOperand | ArmImmOperand | ArmMemOperand |
    ArmFpOperand | ArmCimmOperand | ArmPimmOperand | ArmSetendOperand |
    ArmSysregOperand;
    type ArmRegister =
    | 'r0'
    | 'r1'
    | 'r2'
    | 'r3'
    | 'r4'
    | 'r5'
    | 'r6'
    | 'r7'
    | 'r8'
    | 'r9'
    | 'r10'
    | 'r11'
    | 'r12'
    | 'r13'
    | 'r14'
    | 'r15'
    | 'sp'
    | 'lr'
    | 'sb'
    | 'sl'
    | 'fp'
    | 'ip'
    | 'pc'
    ;

type ArmSystemRegister = 'apsr-nzcvq';

type ArmConditionCode =
    | 'eq'
    | 'ne'
    | 'hs'
    | 'lo'
    | 'mi'
    | 'pl'
    | 'vs'
    | 'vc'
    | 'hi'
    | 'ls'
    | 'ge'
    | 'lt'
    | 'gt'
    | 'le'
    | 'al'
    ;

type ArmOperandType =
    | 'reg'
    | 'imm'
    | 'mem'
    | 'fp'
    | 'cimm'
    | 'pimm'
    | 'setend'
    | 'sysreg'
    ;

interface ArmBaseOperand {
    shift?: {
        type: ArmShifter;
        value: number;
    };
    vectorIndex?: number;
    subtracted: boolean;
}

interface ArmRegOperand extends ArmBaseOperand {
    type: 'reg';
    value: ArmRegister;
}

interface ArmImmOperand extends ArmBaseOperand {
    type: 'imm';
    value: number;
}

interface ArmMemOperand extends ArmBaseOperand {
    type: 'mem';
    value: {
        base?: ArmRegister;
        index?: ArmRegister;
        scale: number;
        disp: number;
    };
}

interface ArmFpOperand extends ArmBaseOperand {
    type: 'fp';
    value: number;
}

interface ArmCimmOperand extends ArmBaseOperand {
    type: 'cimm';
    value: number;
}

interface ArmPimmOperand extends ArmBaseOperand {
    type: 'pimm';
    value: number;
}

interface ArmSetendOperand extends ArmBaseOperand {
    type: 'setend';
    value: Endian;
}

interface ArmSysregOperand extends ArmBaseOperand {
    type: 'sysreg';
    value: ArmRegister;
}

type ArmShifter =
    | 'asr'
    | 'lsl'
    | 'lsr'
    | 'ror'
    | 'rrx'
    | 'asr-reg'
    | 'lsl-reg'
    | 'lsr-reg'
    | 'ror-reg'
    | 'rrx-reg'
    ;

type Arm64Operand = Arm64RegOperand | Arm64ImmOperand | Arm64MemOperand |
    Arm64FpOperand | Arm64CimmOperand | Arm64RegMrsOperand | Arm64RegMsrOperand |
    Arm64PstateOperand | Arm64SysOperand | Arm64PrefetchOperand | Arm64BarrierOperand;

type Arm64OperandType =
    | 'reg'
    | 'imm'
    | 'mem'
    | 'fp'
    | 'cimm'
    | 'reg-mrs'
    | 'reg-msr'
    | 'pstate'
    | 'sys'
    | 'prefetch'
    | 'barrier'
    ;

interface Arm64BaseOperand {
    shift?: {
        type: Arm64Shifter;
        value: number;
    };
    ext?: Arm64Extender;
    vas?: Arm64Vas;
    vectorIndex?: number;
}

interface Arm64RegOperand extends Arm64BaseOperand {
    type: 'reg';
    value: Arm64Register;
}

interface Arm64ImmOperand extends Arm64BaseOperand {
    type: 'imm';
    value: Int64;
}

interface Arm64MemOperand extends Arm64BaseOperand {
    type: 'mem';
    value: {
        base?: Arm64Register;
        index?: Arm64Register;
        disp: number;
    };
}

interface Arm64FpOperand extends Arm64BaseOperand {
    type: 'fp';
    value: number;
}

interface Arm64CimmOperand extends Arm64BaseOperand {
    type: 'cimm';
    value: Int64;
}

interface Arm64RegMrsOperand extends Arm64BaseOperand {
    type: 'reg-mrs';
    value: Arm64Register;
}

interface Arm64RegMsrOperand extends Arm64BaseOperand {
    type: 'reg-msr';
    value: Arm64Register;
}

interface Arm64PstateOperand extends Arm64BaseOperand {
    type: 'pstate';
    value: number;
}

interface Arm64SysOperand extends Arm64BaseOperand {
    type: 'sys';
    value: number;
}

interface Arm64PrefetchOperand extends Arm64BaseOperand {
    type: 'prefetch';
    value: number;
}

interface Arm64BarrierOperand extends Arm64BaseOperand {
    type: 'barrier';
    value: number;
}

type Arm64Shifter =
    | 'lsl'
    | 'msl'
    | 'lsr'
    | 'asr'
    | 'ror'
    ;

type Arm64Extender =
    | 'uxtb'
    | 'uxth'
    | 'uxtw'
    | 'uxtx'
    | 'sxtb'
    | 'sxth'
    | 'sxtw'
    | 'sxtx'
    ;

type Arm64Vas =
    | '8b'
    | '16b'
    | '4h'
    | '8h'
    | '2s'
    | '4s'
    | '1d'
    | '2d'
    | '1q'
    ;

    type Arm64Register =
    | 'x0'
    | 'x1'
    | 'x2'
    | 'x3'
    | 'x4'
    | 'x5'
    | 'x6'
    | 'x7'
    | 'x8'
    | 'x9'
    | 'x10'
    | 'x11'
    | 'x12'
    | 'x13'
    | 'x14'
    | 'x15'
    | 'x16'
    | 'x17'
    | 'x18'
    | 'x19'
    | 'x20'
    | 'x21'
    | 'x22'
    | 'x23'
    | 'x24'
    | 'x25'
    | 'x26'
    | 'x27'
    | 'x28'
    | 'x29'
    | 'x30'
    | 'w0'
    | 'w1'
    | 'w2'
    | 'w3'
    | 'w4'
    | 'w5'
    | 'w6'
    | 'w7'
    | 'w8'
    | 'w9'
    | 'w10'
    | 'w11'
    | 'w12'
    | 'w13'
    | 'w14'
    | 'w15'
    | 'w16'
    | 'w17'
    | 'w18'
    | 'w19'
    | 'w20'
    | 'w21'
    | 'w22'
    | 'w23'
    | 'w24'
    | 'w25'
    | 'w26'
    | 'w27'
    | 'w28'
    | 'w29'
    | 'w30'
    | 'sp'
    | 'lr'
    | 'fp'
    | 'wsp'
    | 'wzr'
    | 'xzr'
    | 'nzcv'
    | 'ip0'
    | 'ip1'
    | 's0'
    | 's1'
    | 's2'
    | 's3'
    | 's4'
    | 's5'
    | 's6'
    | 's7'
    | 's8'
    | 's9'
    | 's10'
    | 's11'
    | 's12'
    | 's13'
    | 's14'
    | 's15'
    | 's16'
    | 's17'
    | 's18'
    | 's19'
    | 's20'
    | 's21'
    | 's22'
    | 's23'
    | 's24'
    | 's25'
    | 's26'
    | 's27'
    | 's28'
    | 's29'
    | 's30'
    | 's31'
    | 'd0'
    | 'd1'
    | 'd2'
    | 'd3'
    | 'd4'
    | 'd5'
    | 'd6'
    | 'd7'
    | 'd8'
    | 'd9'
    | 'd10'
    | 'd11'
    | 'd12'
    | 'd13'
    | 'd14'
    | 'd15'
    | 'd16'
    | 'd17'
    | 'd18'
    | 'd19'
    | 'd20'
    | 'd21'
    | 'd22'
    | 'd23'
    | 'd24'
    | 'd25'
    | 'd26'
    | 'd27'
    | 'd28'
    | 'd29'
    | 'd30'
    | 'd31'
    | 'q0'
    | 'q1'
    | 'q2'
    | 'q3'
    | 'q4'
    | 'q5'
    | 'q6'
    | 'q7'
    | 'q8'
    | 'q9'
    | 'q10'
    | 'q11'
    | 'q12'
    | 'q13'
    | 'q14'
    | 'q15'
    | 'q16'
    | 'q17'
    | 'q18'
    | 'q19'
    | 'q20'
    | 'q21'
    | 'q22'
    | 'q23'
    | 'q24'
    | 'q25'
    | 'q26'
    | 'q27'
    | 'q28'
    | 'q29'
    | 'q30'
    | 'q31'
    ;

type Arm64ConditionCode =
    | 'eq'
    | 'ne'
    | 'hs'
    | 'lo'
    | 'mi'
    | 'pl'
    | 'vs'
    | 'vc'
    | 'hi'
    | 'ls'
    | 'ge'
    | 'lt'
    | 'gt'
    | 'le'
    | 'al'
    | 'nv'
    ;

type Arm64IndexMode = 'post-adjust' | 'signed-offset' | 'pre-adjust';

interface ArmInstruction extends Instruction {
  operands: ArmOperand[];
  regsRead: ArmRegister[];
  regsWritten: ArmRegister[];
}

interface Arm64Instruction extends Instruction {
  operands: Arm64Operand[];
  regsRead: Arm64Register[];
  regsWritten: Arm64Register[];
}

interface Module {
  base: string; // encoded NativePointer
  name: string;
  size: number;
  path: string;
}
