#pragma once

namespace protector {

/** Decrypt .bitcode in-place (no-op unless DECRYPT_BITCODE). */
void decrypt_bitcode();

/** Install hooks / risk. Call from JNI_OnLoad (not .init_array). */
void init_protector();

} // namespace protector
