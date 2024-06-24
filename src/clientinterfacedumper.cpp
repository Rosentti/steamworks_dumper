#include "clientinterfacedumper.h"
#include "randomstack.h"
#include <string>
#include <iostream>
#include <set>
#include <cctype>

ClientInterfaceDumper::ClientInterfaceDumper(ClientModule *t_module):
    DumperBase(t_module),
    m_relRoShdr(nullptr),
    m_txtShdr(nullptr),
    m_roShdr(nullptr),
    m_sendSerializedFnOffset(-1),
    m_clientApiInitGlobal(-1),
    m_utlbufferPutByte(-1),
    m_utlbufferGetBytes(-1),
    m_utlbufferPutBytes(-1),
    m_logIPCCallFailure(-1),
    m_steamFree(-1),
    m_ipcClientFreeFuncCallReturnBuffer(-1),
    m_utlbufferGetUnsignedInt64Offset(-1),
    m_utlbufferPutString(-1),
    m_utlbufferGetString(-1),
    m_assertCannotCallInCrossProcess(-1),
    m_utlbufferPutUnsignedInt64Offset(-1),
    m_utlbufferGetUtlbuffer(-1),
    m_utlbufferPutUtlbuffer(-1),
    m_utlbufferPutProtobuf(-1),
    m_utlbufferPutUtlvector(-1),
    m_strlen(-1)
{
    m_relRoShdr = t_module->GetSectionHeader(".data.rel.ro");
    m_relRoLocalShdr = t_module->GetSectionHeader(".data.rel.ro.local");
    m_roShdr = t_module->GetSectionHeader(".rodata");
    m_txtShdr = t_module->GetSectionHeader(".text");

    m_strlen = t_module->GetImage()->GetImportRelocByName("strlen");

    m_ipcClientFreeFuncCallReturnBuffer = t_module->FindSignature(
        "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\x8B\x00\x00\x00\x85\xFF\x74\x00\x83\xEC\x00\x8B", 
        "xxxxx????xx????xx?x???xxx?xx?x"
    );

    m_sendSerializedFnOffset = t_module->FindSignature(
        "\x55\x89\xE5\x57\x56\xE8\x00\x00\x00\x00\x81\xC6\x00\x00\x00\x00\x53\x81\xEC\x00\x00\x00\x00\x8B\x45\x08\x89\x85\x00\x00\x00\x00\x8B\x45\x10\x8B\xBE\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00",
        "xxxxxx????xx????xxx????xxxxx????xxxxx????xx????"
    );

    // CUtlBuffer* this, byte
    m_utlbufferPutByte = t_module->FindSignature(
        "\xE8\x00\x00\x00\x00\x81\xC2\x00\x00\x00\x00\x57\x56\x53\x83\xEC\x00\x65\x00\x00\x00\x00\x00\x00\x44\x00\x00\x31\xC0\x8B\x00\x00\x00\x8B\x00\x00\x00\x0F\x00\x00\x00\xA8\x01\x75\x00\x0F\x00\x00\x00\x83\xE0\x00\x83\xE2\x00\x08\xC2\x75\x00\xBA\x01",
        "x????xx????xxxxx?x??????x??xxx???x???x???xxx?x???xx?xx?xxx?xx"
    );

    // CUtlBuffer* this, void*, int length
    m_utlbufferPutBytes = t_module->FindSignature(
        "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\x8B\x00\x00\x00\x8B\x00\x00\x00\x8B\x00\x00\x00\x85\xFF\x7F",
        "xxxxx????xx????xx?x???x???x???xxx"
    );

    m_utlbufferGetBytes = t_module->FindSignature(
        "\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\x8B\x00\x00\x00\x8B\x00\x00\x00\x8B\x00\x00\x00\x8B\x00\x00\x2B\x00\x00\x39",
        "xxx????xx????xx?x???x???x???x??x??x"
    );

    // const char*, const char*, int
    m_logIPCCallFailure = t_module->FindSignature(
        "\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\x0F\x00\x00\x00\x00\x50\x00\x00\x00\x00\x8D",
        "xx????xx????xx?x????x????x"
    );

    m_steamFree = t_module->FindSignature(
        "\xE8\x00\x00\x00\x00\x81\xC2\x00\x00\x00\x00\x83\xEC\x00\x8B\x00\x00\x00\x8B\x00\x00\x85\xC9",
        "x????xx????xx?x???x??xx"
    );

    // CUtlBuffer* this, uint64_t* out
    m_utlbufferGetUnsignedInt64Offset = t_module->FindSignature(
        "\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\x8B\x00\x00\x00\x8B\x00\x00\x00\x8B\x00\x00\x2B",
        "xxx????xx????xx?x???x???x??x"
    );

    m_utlbufferPutUnsignedInt64Offset = t_module->FindSignature(
        "\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\xF3\x00\x00\x00\x00\x00\x00\x0F\x00\x00\x00\x00\x6A", 
        "xx????xx????xx?x??????x????x"
    );

    m_utlbufferGetProtobuf = t_module->FindSignature(
        "\x57\x56\x53\x8B\x74\x24\x10\x00\x00\x00\x00\x00\x81\xC3\xC4\xAD\xA0\x01\x83\xEC\x0C\x56\x00\x00\x00\x00\x00\x83\xC4\x0C\x50\x89\xC7", 
        "xxxxxxx?????xxxxxxxxxx?????xxxxxx"
    );

    m_utlbufferPutProtobuf = t_module->FindSignature(
        "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\x8B\x00\x00\x00\x8B\x00\x00\x00\x8B\x00\x00\x8D\x00\x00\x00\x00\x00\x8B\x00\x00\x39\xD0\x75\x00\x8B", 
        "xxxxx????xx????xx?x???x???x??x?????x??xxx?x"
    );

    m_utlbufferGetUtlbuffer = t_module->FindSignature(
        "\x57\x56\x53\x8B\x74\x24\x10\x00\x00\x00\x00\x00\x81\xC3\xF4\xAC\xA0\x01\x83\xEC\x0C\x56\x00\x00\x00\x00\x00\x83\xC4\x0C\x50\x89", 
        "xxxxxxx?????xxxxxxxxxx?????xxxxx"
    );

    m_utlbufferPutUtlbuffer = t_module->FindSignature(
        "\x57\x56\x53\x8B\x74\x24\x14\x00\x00\x00\x00\x00\x81\xC3\xD4\x98\xA0\x01\x8B\x7C\x24\x10\x83\xEC\x08\xFF\x76\x14\x57\x00\x00\x00\x00\x00\x83\xC4", 
        "xxxxxxx?????xxxxxxxxxxxxxxxxx?????xx"
    );

    m_utlbufferPutSteamNetworkingIdentity = t_module->FindSignature(
        "\x57\x56\x53\x8B\x00\x00\x00\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x8B\x00\x00\x00\x85\xFF\x74\x00\x83\xEC\x00\x68", 
        "xxxx???x????xx????x???xxx?xx?x"
    );

    m_utlbufferPutUtlvector = t_module->FindSignature(
        "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x00\x8B\x00\x00\x00\x85\xED\x74\x00\x8B", 
        "xxxxx????xx????xx?x???xxx?x"
    );

    // Can't find a signature for this. Instead we do a janky hack
    // CUtlBuffer* this, const char* str
    //m_utlbufferPutString = t_module->FindSignature();

    m_clientApiInitGlobal = t_module->FindSignature("\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x0C\x8B\x83\x00\x00\x00\x00\x8B\x10\xFF\xB3\x00\x00\x00\x00\xFF\xB3\x00\x00\x00\x00\x50\xFF\x52\x20",
        "xx????xx????xxxxx????xxxx????xx????xxxx"
    );

    if(m_sendSerializedFnOffset == -1)
    {
        std::cout << "Could not find SendSerializedFunction offset!" << std::endl;
    }

    if(m_utlbufferPutByte == -1)
    {
        std::cout << "Could not find CUtlBuffer::PutByte offset!" << std::endl;
    }

    if(m_utlbufferPutBytes == -1)
    {
        std::cout << "Could not find CUtlBuffer::PutBytes offset!" << std::endl;
    }

    if(m_utlbufferGetBytes == -1)
    {
        std::cout << "Could not find CUtlBuffer::GetBytes offset!" << std::endl;
    }

    if (m_logIPCCallFailure == -1) 
    {
        std::cout << "Could not find LogIPCCallFailure offset!" << std::endl;
    }

    if (m_steamFree == -1) 
    {
        std::cout << "Could not find SteamFree offset!" << std::endl;
    }

    if (m_ipcClientFreeFuncCallReturnBuffer == -1) 
    {
        std::cout << "Could not find CIPCClient::FreeFuncCallReturnBuffer offset!" << std::endl;
    }

    if (m_utlbufferGetUnsignedInt64Offset == -1) 
    {
        std::cout << "Could not find CUtlBuffer::GetUnsignedInt64 offset!" << std::endl;
    }

    if (m_utlbufferPutUnsignedInt64Offset == -1) 
    {
        std::cout << "Could not find CUtlBuffer::PutUnsignedInt64 offset!" << std::endl;
    }

    if (m_utlbufferGetProtobuf == -1) 
    {
        std::cout << "Could not find CUtlBuffer::GetProtobuf offset!" << std::endl;
    }

    if (m_utlbufferPutProtobuf == -1)
    {
        std::cout << "Could not find CUtlBuffer::PutProtobuf offset!" << std::endl;
    }

    if (m_utlbufferGetUtlbuffer == -1) 
    {
        std::cout << "Could not find CUtlBuffer::GetUtlBuffer offset!" << std::endl;
    }

    if (m_utlbufferPutUtlbuffer == -1) 
    {
        std::cout << "Could not find CUtlBuffer::PutUtlBuffer offset!" << std::endl;
    }

    if (m_utlbufferPutSteamNetworkingIdentity == -1) 
    {
        std::cout << "Could not find CUtlBuffer::PutSteamNetworkingIdentity offset!" << std::endl;
    }

    if (m_utlbufferPutUtlvector == -1)
    {
        std::cout << "Could not find CUtlBuffer::PutCUtlVector offset!" << std::endl;
    } 

    if(m_clientApiInitGlobal == -1)
    {
        std::cout << "Could not find ClientAPI_Init offset..." << std::endl;
    }

    if (m_strlen == -1) 
    {
        std::cout << "Could not find strlen import!" << std::endl;
    } else {
        std::cout << "Strlen import at " << (void*)m_strlen << std::endl;
    }
}

ClientInterfaceDumper::~ClientInterfaceDumper()
{

}

bool ClientInterfaceDumper::GetSerializedFuncInfo(std::string t_iname, size_t t_offset, size_t* t_argc, std::string* t_name, uint8_t* interfaceid, uint32_t* functionid, uint32_t* fencepost, std::vector<std::string>* serializedArgs, std::vector<std::string>* serializedReturns, std::string *serializedReturn, bool *cannotCallInCrossProcess)
{
    size_t funcSize = m_module->GetFunctionSize(t_offset);
    if(funcSize == -1)
    {
        return false;
    }

    csh csHandle;
    cs_insn *ins;
    size_t count;
    std::set<int32_t> args;
    bool hasSetFunctionId = false;
    bool hasSetFencepost = false;
    bool hasSetInterfaceId = false;
    bool isFirstUtlbufWrite = true;
    bool isInResultDeserialization = false;
    bool hasSkippedFunctionIDFunc = false;
    bool isInArgsDeserialization = false;
    bool haveDeserializedArgs = false;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) == CS_ERR_OK)
    {
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

        RandomAccessStack ras;

        std::cout << std::endl;
        count = cs_disasm(csHandle, (uint8_t *)(m_image + t_offset), funcSize, t_offset, 0, &ins);
        if(count > 0)
        {
            for (size_t i = 0; i < count; i++)
            {
                //printf("0x%" PRIx64":\t%s\t\t%s\n", ins[i].address, ins[i].mnemonic, ins[i].op_str);
                cs_x86* x86 = &ins[i].detail->x86;

                ras.Update(&ins[i]);

                switch(ins[i].id)
                {
                    case X86_INS_PUSH:
                    case X86_INS_FLD:
                    {
                        if( x86->operands[0].mem.base == X86_REG_EBP
                            && x86->disp > 0
                        )
                        {
                            args.insert(x86->disp);
                        }
                        break;
                    }
                    case X86_INS_LEA:
                    case X86_INS_MOV:
                    {
                        // This is hacky and terrible.
                        if (ins[i].id == X86_INS_MOV && x86->operands[1].type == X86_OP_IMM) {
                            if (!hasSetFencepost && x86->operands[1].mem.base == X86_REG_INVALID && x86->operands[1].imm <= UINT32_MAX && x86->operands[1].imm > 255 && x86->operands[1].imm != *functionid) {
                                if (hasSetFunctionId) {
                                    *fencepost = x86->operands[1].imm;
                                    hasSetFencepost = true;
                                }
                                else
                                {
                                    *functionid = x86->operands[1].imm;
                                    hasSetFunctionId = true;
                                }
                            }
                        }

                        if(x86->operands[1].type == X86_OP_MEM)
                        {
                            if( x86->operands[1].mem.base == X86_REG_EBP
                                     && x86->disp > 0
                            )
                            {
                                // no idea how many times args could be addressed
                                // so just store stack offsets above stack
                                // reserve for local vars from function prologue in a set
                                // that should give us approximate count of function args
                                args.insert(x86->disp);
                            }
                        }

                        break;
                    }

                    case X86_INS_TEST:
                    {
                        // This truly is terrible
                        if (isInResultDeserialization) {
                            if (i > 1 && ins[i-1].id == X86_INS_ADD) {
                                if (ins[i-1].detail->x86.operands[1].imm == 0x10) {
                                    isInResultDeserialization = false;
                                    haveDeserializedArgs = true;
                                }
                            }
                        }

                        break;
                    }

                    case X86_INS_CALL:
                    {
                        if (CheckIfAssertCannotCallInCrossProcessFunc(csHandle, x86->operands[0].imm)) {
                            *cannotCallInCrossProcess = true;
                        }

                        if (hasSetFunctionId && hasSetFencepost && !haveDeserializedArgs) {
                            if (x86->operands[0].imm == m_steamFree) {
                                isInResultDeserialization = true;
                                break;
                            }
                        }

                        if (isInResultDeserialization) {
                            if (x86->operands[0].imm == m_logIPCCallFailure) {
                                isInResultDeserialization = false;
                                haveDeserializedArgs = true;
                                break;
                            }

                            if (x86->operands[0].imm == m_ipcClientFreeFuncCallReturnBuffer) {
                                isInResultDeserialization = false;
                                haveDeserializedArgs = true;
                                break;
                            }
                        }

                        if(x86->operands[0].imm == m_sendSerializedFnOffset)
                        {
                            if (ras.Size() > 4)
                            {
                                int32_t stackOffset = ras.GetOffset();
                                size_t nameOffset = m_constBase + ras[stackOffset - 16]->disp;
                                if(m_module->IsDataOffset(nameOffset))
                                {
                                    *t_name = (const char*)(m_image + nameOffset);
                                }
                            }
                        }
                        
                        if (x86->operands[0].imm == m_utlbufferPutByte) {
                            if (!hasSetInterfaceId)
                            {
                                // Skip the first write, as it is the IPC command code
                                if (isFirstUtlbufWrite) {
                                    isFirstUtlbufWrite = false;
                                    break;
                                }

                                int32_t stackOffset = ras.GetOffset();
                                auto byte = ras[stackOffset - 4]->operands[0].imm;

                                if (byte == 0) {
                                    throw std::runtime_error("0 is not a valid interface ID.");
                                }

                                if (byte > 64) {
                                    // Change this when there are more than 64 interface ID's used.
                                    // Don't change it to crazy values like 200 though, since this is useful to keep as a sanity check.
                                    throw std::runtime_error("Max interface id is 64. The current ID '" + std::to_string(byte) + "' is too high. ");
                                }

                                hasSetInterfaceId = true;
                                *interfaceid = (uint8_t)byte;
                            }
                        }

                        // Handle arguments
                        if (hasSetFunctionId && !hasSetFencepost) {
args_start_of_if:
                            if (CheckIfAssertCannotCallInCrossProcessFunc(csHandle, x86->operands[0].imm)) {
                                *cannotCallInCrossProcess = true;
                                break;
                            } else if (x86->operands[0].imm == m_utlbufferPutByte) {
                                serializedArgs->push_back(std::string("byte"));
                            } else if (x86->operands[0].imm == m_utlbufferPutBytes) {
                                if (hasSkippedFunctionIDFunc) {
                                    int32_t stackOffset = ras.GetOffset();
                                    std::string as_str = "unknown";
                                    if (ras[stackOffset - 8]->operands[0].type == x86_op_type::X86_OP_IMM)
                                    {
                                        auto byteCount = ras[stackOffset - 8]->operands[0].imm;
                                        as_str = std::string("bytes") + std::to_string(byteCount);
                                    } else if (ras[stackOffset - 8]->operands[0].type == x86_op_type::X86_OP_MEM) {
                                        as_str = std::string("bytes_length_from_mem");
                                    } else if (ras[stackOffset - 8]->operands[0].type == x86_op_type::X86_OP_REG) {
                                        as_str = std::string("bytes_length_from_reg");
                                    }
                                    serializedArgs->push_back(std::string(as_str));
                                } else {
                                    hasSkippedFunctionIDFunc = true;
                                }
                            } else if (x86->operands[0].imm == m_utlbufferPutString) {
                                serializedArgs->push_back(std::string("string"));  
                            } else if (x86->operands[0].imm == m_utlbufferPutUnsignedInt64Offset) {
                                serializedArgs->push_back(std::string("uint64"));
                            } else if (x86->operands[0].imm == m_utlbufferPutUtlbuffer) {
                                serializedArgs->push_back(std::string("utlbuffer"));
                            } else if (x86->operands[0].imm == m_utlbufferPutProtobuf) {
                                serializedArgs->push_back(std::string("protobuf"));
                            } else if (x86->operands[0].imm == m_utlbufferPutSteamNetworkingIdentity) {
                                serializedArgs->push_back(std::string("steamnetworkingidentity"));
                            } else if (x86->operands[0].imm == m_utlbufferPutUtlvector) {
                                serializedArgs->push_back(std::string("utlvector"));
                            } else {
                                if (CheckIfPutStringFunc(csHandle, x86->operands[0].imm)) {
                                    goto args_start_of_if;
                                }
                                serializedArgs->push_back(std::string("unknown"));
                            }
                        }

                        // Handle returns
                        if (isInResultDeserialization) {
result_start_of_if:
                            if (x86->operands[0].imm == m_utlbufferGetBytes) {
                                int32_t stackOffset = ras.GetOffset();
                                auto byteCount = ras[stackOffset - 8]->operands[0].imm;
                                auto as_str = std::string("bytes") + std::to_string(byteCount);
                                bool inferredType = false;
                                
                                switch (ras[stackOffset - 8]->operands[0].type)
                                {
                                    case x86_op_type::X86_OP_MEM:
                                        as_str = std::string("bytes_length_from_mem");
                                        break;

                                    case x86_op_type::X86_OP_REG:
                                        as_str = std::string("bytes_length_from_reg");
                                        break;
                                    
                                    default:
                                        break;
                                }

                                // More than likely a boolean if the name follows this format B[uppercase letter] (side note: this is terrible)
                                if (!inferredType && as_str == "bytes1" && !t_name->empty() && t_name->length() > 2 && (*t_name)[0] == 'B' && std::isupper(static_cast<unsigned char>((*t_name)[1]))) {
                                    as_str = "boolean";
                                    inferredType = true;
                                }

                                // Also likely a boolean if the name starts with "Is"
                                if (!inferredType && as_str == "bytes1" && !t_name->empty() && t_name->length() > 2 && (*t_name)[0] == 'I' && (*t_name)[1] == 's') {
                                    as_str = "boolean";
                                    inferredType = true;
                                }

                                serializedReturns->push_back(as_str);
                            } else if (x86->operands[0].imm == m_utlbufferGetUnsignedInt64Offset) {
                                serializedReturns->push_back(std::string("uint64"));
                            } else if (x86->operands[0].imm == m_utlbufferGetString) {
                                serializedReturns->push_back(std::string("string"));  
                            } else if (x86->operands[0].imm == m_utlbufferGetProtobuf) {
                                serializedReturns->push_back(std::string("protobuf"));
                            } else if (x86->operands[0].imm == m_utlbufferGetUtlbuffer) {
                                serializedReturns->push_back(std::string("utlbuffer"));
                            } else {
                                if (CheckIfGetStringFunc(csHandle, x86->operands[0].imm)) {
                                    goto result_start_of_if;
                                }
                                printf("unknown_ret: 0x%" PRIx64":\t%s\t\t%s\n", ins[i].address, ins[i].mnemonic, ins[i].op_str);
                                serializedReturns->push_back(std::string("unknown"));
                            }
                        }

                        break;
                    }
                }
            }
            cs_free(ins, count);
        }
    }
    cs_close(&csHandle);

    *t_argc = args.size();

    if (*functionid == 0 || *fencepost == 0) {
        std::cout << "WARNING: No IPC info for function " << t_iname << "::" << *t_name << std::endl;
    }

    std::cout << "Stop dumping function " << t_iname << "::" << *t_name << std::endl;

    return true;
}

// Sketchy stuff to find CUtlBuffer::PutString func
bool ClientInterfaceDumper::CheckIfPutStringFunc(csh csHandle, size_t funcOffset) {
    if (m_utlbufferPutString != -1 || m_strlen == -1) {
        return false;
    }

    size_t funcSize = m_module->GetFunctionSize(funcOffset);
    if(funcSize == -1)
    {
        return false;
    }

    std::cout << "PutString candidate" << std::endl;
    RandomAccessStack ras;
    cs_insn *ins;
    size_t count;
    count = cs_disasm(csHandle, (uint8_t *)(m_image + funcOffset), funcSize, funcOffset, 0, &ins);
    if(count > 0)
    {
        for (size_t i = 0; i < count; i++)
        {
            //printf("0x%" PRIx64":\t%s\t\t%s\n", ins[i].address, ins[i].mnemonic, ins[i].op_str);
            cs_x86* x86 = &ins[i].detail->x86;

            ras.Update(&ins[i]);

            switch(ins[i].id)
            {
                case X86_INS_CALL:
                {
                    if(x86->operands[0].imm == m_strlen)
                    {
                        std::cout << "strlen" << std::endl;
                        m_utlbufferPutString = funcOffset;
                        break;
                    }
                }
            }
        }
        cs_free(ins, count);
    }

    std::cout << "PutString candidate end" << std::endl;
    
    return m_utlbufferPutString != -1;
}

// Sketchy stuff to find CUtlBuffer::GetString func
bool ClientInterfaceDumper::CheckIfGetStringFunc(csh csHandle, size_t funcOffset) {
    if (m_utlbufferGetString != -1 || m_strlen == -1) {
        return false;
    }
    
    size_t funcSize = m_module->GetFunctionSize(funcOffset);
    if(funcSize == -1)
    {
        return false;
    }

    RandomAccessStack ras;
    cs_insn *ins;
    size_t count;
    count = cs_disasm(csHandle, (uint8_t *)(m_image + funcOffset), funcSize, funcOffset, 0, &ins);
    if(count > 0)
    {
        for (size_t i = 0; i < count; i++)
        {
            cs_x86* x86 = &ins[i].detail->x86;

            ras.Update(&ins[i]);

            switch(ins[i].id)
            {
                case X86_INS_CALL:
                {
                    if(x86->operands[0].imm == m_strlen)
                    {
                        std::cout << "strlen call" << std::endl;
                        m_utlbufferGetString = funcOffset;
                        break;
                    }
                }
            }
        }
        cs_free(ins, count);
    }
    
    return m_utlbufferGetString != -1;
}

// Sketchy stuff to check if any function call is AssertCannotCallInCrossProcess
bool ClientInterfaceDumper::CheckIfAssertCannotCallInCrossProcessFunc(csh csHandle, size_t funcOffset) {
    if (m_assertCannotCallInCrossProcess != -1) {
        if (m_assertCannotCallInCrossProcess == funcOffset)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    if (funcOffset == m_sendSerializedFnOffset || funcOffset == m_steamFree || funcOffset == m_clientApiInitGlobal || funcOffset == m_logIPCCallFailure || funcOffset == m_utlbufferGetBytes || funcOffset == m_utlbufferGetString || funcOffset == m_utlbufferGetUnsignedInt64Offset || funcOffset == m_utlbufferPutByte || funcOffset == m_utlbufferPutBytes || funcOffset == m_utlbufferPutString || funcOffset == m_utlbufferPutUnsignedInt64Offset) {
        return false;
    }

    size_t funcSize = m_module->GetFunctionSize(funcOffset);
    if(funcSize == -1)
    {
        return false;
    }

    std::cout << "AssertCannotCallInCrossProcess candidate" << std::endl;
    RandomAccessStack ras;
    cs_insn *ins;
    size_t count;
    bool haveInt3 = false;
    count = cs_disasm(csHandle, (uint8_t *)(m_image + funcOffset), funcSize, funcOffset, 0, &ins);
    if(count > 0)
    {
start_of_loop:
        for (size_t i = 0; i < count; i++)
        {
            //printf("0x%" PRIx64":\t%s\t\t%s\n", ins[i].address, ins[i].mnemonic, ins[i].op_str);
            cs_x86* x86 = &ins[i].detail->x86;

            ras.Update(&ins[i]);

            switch (ins[i].id)
            {
                case X86_INS_INT3:
                {
                    if (!haveInt3) {
                        haveInt3 = true;
                        goto start_of_loop;
                    }
                    break;
                }

                case X86_INS_CALL:
                {
                    if (haveInt3) {
                        std::cout << "function call" << std::endl;
                        if (ras.Size() > 8)
                        {
                            int32_t stackOffset = ras.GetOffset();
                            if (ras[stackOffset - 8] == nullptr)
                            {
                                // Nullptr check
                                goto start_of_loop;
                            }
                            size_t assertOffset = m_constBase + ras[stackOffset - 8]->disp;
                            if(m_module->IsDataOffset(assertOffset))
                            {
                                if (std::string((const char *)(m_image + assertOffset)) == "Cannot call %s::%s in cross-process pipe!")
                                {
                                    m_assertCannotCallInCrossProcess = funcOffset;
                                    break;
                                }
                            }
                        }
                    }
                }

                default:
                    break;
            }

            if (m_assertCannotCallInCrossProcess != -1) {
                break;
            }
        }
        cs_free(ins, count);
    }

    std::cout << "AssertCannotCallInCrossProcess candidate end" << std::endl;
    if (m_assertCannotCallInCrossProcess != -1) {
        std::cout << "AssertCannotCallInCrossProcess found" << std::endl;
    }
    return m_assertCannotCallInCrossProcess != -1;
}

size_t ClientInterfaceDumper::GetIClientEngine()
{
    // ClientAPI_Init is relatively simple function
    // that initializes client global context and throwing assert
    // on any NULL returned by interface getter in IClientEngine
    // Like this one:
    // "ClientAPI_Init(GlobalInstance): GetIClientSystemPerfManager returned NULL."
    //
    // we'll use these assert strings to partially recover
    // IClientEngine interface

    size_t funcSize = m_module->GetFunctionSize(m_clientApiInitGlobal);
    if(funcSize == -1)
    {
        return false;
    }

    std::string iname("IClientEngineMap");

    csh csHandle;
    cs_insn *ins;
    size_t count;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) == CS_ERR_OK)
    {
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(csHandle, (uint8_t*)(m_image + m_clientApiInitGlobal), funcSize, m_clientApiInitGlobal, 0, &ins);
        if(count > 0)
        {
            // Parser's a mess, but i really want to get it all in one pass

            int32_t lastCallOff = -1;
            int argc = 0;

            std::map<size_t, int32_t> stringHints;
            std::map<int32_t, InterfaceFunction> funcs;

            for (size_t i = 0; i < count; i++)
            {
                cs_x86* x86 = &ins[i].detail->x86;
                cs_insn* insSingle = &ins[i];

                switch(ins[i].id)
                {
                case X86_INS_JE:
                {
                    if(lastCallOff != -1)
                    {
                        // probably jump to assert on returned NULL
                        // if that's the case it'll be jump to LEA
                        // with assert string offset
                        stringHints[x86->operands[0].imm] = lastCallOff;
                        lastCallOff = -1;
                    }
                    break;
                }
                case X86_INS_PUSH:
                {
                    ++argc;
                    break;
                }
                case X86_INS_LEA:
                {
                    size_t constOffset = m_constBase + x86->disp;
                    if(m_module->IsDataOffset(constOffset))
                    {
                        if(stringHints.find(ins[i].address) != stringHints.cend())
                        {
                            // Skip "ClientAPI_Init(GlobalInstance): "
                            std::string ass = (const char*)(m_image + constOffset + 32);
                            funcs[stringHints[ins[i].address]].m_name = ass.substr(0, ass.find_first_of(' '));
                        }
                    }
                    break;
                }
                case X86_INS_CALL:
                {
                    if(    x86->op_count == 1
                        && x86->operands[0].type == X86_OP_MEM
                        )
                    {
                        funcs[x86->operands[0].mem.disp].m_addr = x86->operands[0].mem.disp;
                        funcs[x86->operands[0].mem.disp].m_argc = argc;

                        lastCallOff = x86->operands[0].mem.disp;
                    }
                    argc = 0;
                    break;
                }
                }
            }

            if(funcs.size() > 0)
            {
                m_interfaces[iname].m_foundAt = m_clientApiInitGlobal;

                for(int32_t i = 0; i < (--funcs.end())->first + sizeof(int32_t); i += sizeof(int32_t))
                {
                    if(    funcs.find(i) != funcs.cend()
                        && !funcs[i].m_name.empty()
                      )
                    {
                        m_interfaces[iname].m_functions.push_back(funcs[i]);
                    }
                    else
                    {
                        InterfaceFunction funk = { "Unknown_" + std::to_string( i / sizeof(int32_t)), 0, 0 };
                        m_interfaces[iname].m_functions.push_back(funk);
                    }
                }
            }
        }
    }

    return -1;
}

void ClientInterfaceDumper::ParseVTable(std::string t_typeName, size_t t_vtoffset)
{
    int32_t* vtFuncs = (int32_t*)(m_image + t_vtoffset);
    int vmIdx = 0;
    while(   vtFuncs[vmIdx] != 0
          && vtFuncs[vmIdx] <= m_txtShdr->sh_addr + m_txtShdr->sh_size
          && vtFuncs[vmIdx] > m_txtShdr->sh_addr
         )
    {
        std::string fName;
        size_t fArgc = 0;
        InterfaceFunction func;
        uint8_t interfaceId = 0;
        uint32_t functionid = 0;
        uint32_t fencepost = 0;
        std::vector<std::string> serializedArgs;
        std::vector<std::string> serializedReturns;
        std::string serializedReturn;
        bool cannotCallInCrossProcess = false;

        if (!GetSerializedFuncInfo(t_typeName, vtFuncs[vmIdx], &fArgc, &fName, &interfaceId, &functionid, &fencepost, &serializedArgs, &serializedReturns, &serializedReturn, &cannotCallInCrossProcess) || fName.empty())
        {
            fName = "Unknown_" + std::to_string(vmIdx);
        }

        func.m_addr = vtFuncs[vmIdx];
        func.m_argc = fArgc;
        func.m_name = fName;
        func.m_interfaceid = interfaceId;
        func.m_functionid = functionid;
        func.m_fencepost = fencepost;
        func.m_serializedargs = serializedArgs;
        func.m_serializedreturns = serializedReturns;
        func.m_cannotcallincrossprocess = cannotCallInCrossProcess;
        m_interfaces[t_typeName].m_functions.push_back(func);

        ++vmIdx;
    }
}

size_t ClientInterfaceDumper::FindClientInterfaces()
{
    std::vector<size_t> vtInfos;
    if(    !m_module->GetVTTypes(&vtInfos)
        || !m_relRoShdr
        || m_sendSerializedFnOffset == -1
      )
    {
        return 0;
    }

    auto consts = m_module->GetConstants();

    for(auto it = vtInfos.cbegin(); it != vtInfos.cend(); ++it)
    {
        size_t strOffset = *(int32_t*)(m_image + *it + 4);
        std::string_view vtName(m_image + strOffset);
        if((vtName.find("IClient") != std::string_view::npos || vtName.find("IRegistry") != std::string_view::npos)
            && vtName.find("Map") != std::string_view::npos
            && vtName.find("Base") == std::string_view::npos
          )
        {
            for(auto cit = consts->cbegin(); cit != consts->cend(); ++cit)
            {
                if(*(int32_t*)(m_image + cit->first - 4) == *it)
                {
                    auto startIndex = vtName.find("IClient");
                    if (startIndex == std::string_view::npos) {
                        startIndex = vtName.find("IRegistry");
                    }

                    std::string iname(vtName.substr(startIndex));
                    m_interfaces[iname].m_foundAt = cit->first;
                    ParseVTable(iname, cit->first);
                }
            }
        }
    }

    if(m_clientApiInitGlobal != -1)
    {
        GetIClientEngine();
    }

    return m_interfaces.size();
}

const std::map<std::string, ClientInterface>* ClientInterfaceDumper::GetInterfaces()
{
    return &m_interfaces;
}
