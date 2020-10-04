//
// Created by dyf on 2020/10/3.
//
#include "odec/capstone2llvmir/capstone2llvmir.h"


#include "odec/capstone2llvmir/x86/x86_impl.h"

namespace odec {
    namespace capstone2llvmir {

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createArch(
                cs_arch a,
                llvm::Module *m,
                cs_mode basic,
                cs_mode extra) {
            switch (a) {
#ifdef OPEN_OTHER
                case CS_ARCH_ARM: {
                    if (basic == CS_MODE_ARM) return createArm(m, extra);
                    if (basic == CS_MODE_THUMB) return createThumb(m, extra);
                    break;
                }
                case CS_ARCH_ARM64: {
                    return createArm64(m, extra);
                }
                case CS_ARCH_MIPS: {
                    if (basic == CS_MODE_MIPS32) return createMips32(m, extra); // == CS_MODE_32
                    if (basic == CS_MODE_MIPS64) return createMips64(m, extra); // == CS_MODE_64
                    if (basic == CS_MODE_MIPS3) return createMips3(m, extra);
                    if (basic == CS_MODE_MIPS32R6) return createMips32R6(m, extra);
                    break;
                }
#endif
                case CS_ARCH_X86: {
                    if (basic == CS_MODE_16) return createX86_16(m, extra);
                    if (basic == CS_MODE_32) return createX86_32(m, extra);
                    if (basic == CS_MODE_64) return createX86_64(m, extra);
                    break;
                }
#ifdef OPEN_OTHER
                case CS_ARCH_PPC: {
                    if (basic == CS_MODE_32) return createPpc32(m, extra);
                    if (basic == CS_MODE_64) return createPpc64(m, extra);
                    break;
                }
#endif
                case CS_ARCH_SPARC: {
                    return createSparc(m, extra);
                }
                case CS_ARCH_SYSZ: {
                    return createSysz(m, extra);
                }
                case CS_ARCH_XCORE: {
                    return createXcore(m, extra);
                }
                default: {
                    // Nothing.
                    break;
                }
            }

            throw GenericError("Unhandled Capstone architecture or mode.");
        }

#if 0
        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createArm(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorArm_impl>(m, CS_MODE_ARM, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createThumb(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorArm_impl>(m, CS_MODE_THUMB, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createArm64(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorArm64_impl>(m, CS_MODE_ARM, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createMips32(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorMips_impl>(m, CS_MODE_MIPS32, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createMips64(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorMips_impl>(m, CS_MODE_MIPS64, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createMips3(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorMips_impl>(m, CS_MODE_MIPS3, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createMips32R6(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorMips_impl>(m, CS_MODE_MIPS32R6, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createPpc32(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorPowerpc_impl>(m, CS_MODE_32, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createPpc64(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorPowerpc_impl>(m, CS_MODE_64, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createPpcQpx(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorPowerpc_impl>(m, CS_MODE_QPX, extra);
        }
#endif

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createX86_16(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorX86_impl>(m, CS_MODE_16, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createX86_32(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorX86_impl>(m, CS_MODE_32, extra);
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createX86_64(
                llvm::Module *m,
                cs_mode extra) {
            return std::make_unique<Capstone2LlvmIrTranslatorX86_impl>(m, CS_MODE_64, extra);
        }


        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createSparc(
                llvm::Module *m,
                cs_mode extra) {
            throw GenericError("Not implemented.");
            return nullptr;
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createSysz(
                llvm::Module *m,
                cs_mode extra) {
            throw GenericError("Not implemented.");
            return nullptr;
        }

        std::unique_ptr<Capstone2LlvmIrTranslator> Capstone2LlvmIrTranslator::createXcore(
                llvm::Module *m,
                cs_mode extra) {
            throw GenericError("Not implemented.");
            return nullptr;
        }

    } // namespace capstone2llvmir
} // namespace odec
