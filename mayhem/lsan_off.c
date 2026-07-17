/* Fleet policy (SPEC.md 6.1): disable LeakSanitizer preventively at BUILD time. ASan
   use-after-free/overflow and UBSan stay fully on and halting -- only leak detection is affected.

   postfix's harnesses drive MIME and tok822 parsing over attacker-controlled input.
   Both use postfix's own arena-style vstring/vbuf allocators that are intentionally not torn down
   per-iteration, so LSan reports on inputs that are not the defect being hunted.

   A runtime ASan default-options override -- whether compiled in or passed via ASAN_OPTIONS -- is
   forbidden, because Mayhem alone owns the runtime ASAN/LibFuzzer option set, so this is done via
   the sanctioned build-time hook instead. SPEC.md 6.2 item 15 bans the override symbol NAMES
   anywhere under mayhem/, comments included, so the forbidden construct is described in prose here
   rather than named. __lsan_is_turned_off is the sanctioned hook and is NOT the banned construct. */
int __lsan_is_turned_off(void) {
  return 1;
}
