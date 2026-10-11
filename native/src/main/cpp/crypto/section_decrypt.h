#pragma once

namespace protector {

/** Decrypt .bitcode in-place (no-op unless DECRYPT_BITCODE). */
void decrypt_bitcode();

/** Early init: decrypt then install hooks / risk. */
void init_protector();

/**
 * Deferred init (call from JNI_OnLoad): bytehook, dlopen hooks, risk thread.
 * Must run after dlopen completes — constructor-time is unsafe on Android 17+.
 */
void init_protector_late();

} // namespace protector
