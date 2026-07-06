set(host_bin test-runner)
set(host_src test-runner.cpp edge_wrapper.cpp)
set(eyrie_plugins "none")

set(package_name "tests.ke")
set(package_script "./run-test.sh")

###############################################
#                Test Apps                    #
###############################################
# to add a test, (1) add the test to the following variable
set(all_test_bins
  test-stack
  test-loop
  test-malloc
  test-long-nop
  test-fibonacci
  test-fib-bench
  test-attestation
  test-untrusted
  test-data-sealing
  test-lt-user-ocall)

set(slottee_fault_test_bins
  test-lt-user-illegal
  test-lt-user-page-fault
  test-lt-user-illegal-cleanup
  test-lt-user-page-fault-cleanup)

set(slottee_stress_test_bins
  test-lt-user-busy-revoke
  test-lt-user-first-busy-revoke
  test-lt-user-edgecall-stress
  test-lt-user-timer-preempt
  test-lt-user-preempt-sched
  test-lt-user-preempt-multihart
  test-lt-user-preempt-steal
  test-lt-user-preempt-bestvictim
  test-lt-user-ledger
  test-lt-user-matmul
  test-lt-user-lu
  test-lt-user-fft
  test-lt-user-radix
  test-lt-user-mlp
  test-lt-user-revoke-ipi)

set(slottee_explicit_test_bins
  test-lt-user-mint-cap
  test-lt-user-policy
  test-lt-user-watchdog-ttl
  test-lt-user-paper-eval
  test-lt-user-multihart-ticket)

# and (2) define the recipe of the test below:

# stack
add_executable(test-stack stack/stack.S)
target_link_libraries(test-stack ${KEYSTONE_LIB_EAPP})

# loop
add_executable(test-loop loop/loop.s)
target_link_libraries(test-loop ${KEYSTONE_LIB_EAPP})

# malloc
add_executable(test-malloc malloc/malloc.c)
target_link_libraries(test-malloc ${KEYSTONE_LIB_EAPP})

# long-nop
add_executable(test-long-nop long-nop/long-nop.S ${CMAKE_CURRENT_BINARY_DIR}/add_long.S)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/add_long.S
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/long-nop/generate_func.sh 4097
  ${CMAKE_CURRENT_BINARY_DIR}/add_long.S
  ${CMAKE_CURRENT_SOURCE_DIR}/long-nop/nop.s
  ${CMAKE_CURRENT_SOURCE_DIR}/long-nop/func_base.s
  ${CMAKE_CURRENT_SOURCE_DIR}/long-nop/nop.h
)
target_link_libraries(test-long-nop ${KEYSTONE_LIB_EAPP})

# fibonacci
add_executable(test-fibonacci fibonacci/fibonacci.c)
target_link_libraries(test-fibonacci ${KEYSTONE_LIB_EAPP})

# fib-bench
add_executable(test-fib-bench fib-bench/fib-bench.c)
target_link_libraries(test-fib-bench ${KEYSTONE_LIB_EAPP})

# attestation
add_executable(test-attestation attestation/attestation.c attestation/edge_wrapper.c)
target_link_libraries(test-attestation ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})

# untrusted
add_executable(test-untrusted untrusted/untrusted.c untrusted/edge_wrapper.c)
target_link_libraries(test-untrusted ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})

# data-sealing
add_executable(test-data-sealing data-sealing/data-sealing.c)
target_link_libraries(test-data-sealing ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})

# SlotTEE LT user OCALL/resume
add_executable(test-lt-user-ocall lt-user-ocall/lt-user-ocall.c)
target_link_libraries(test-lt-user-ocall ${KEYSTONE_LIB_EAPP})

# SlotTEE RT-authorized capability minting probe
add_executable(test-lt-user-mint-cap lt-user-mint-cap/lt-user-mint-cap.c)
target_link_libraries(test-lt-user-mint-cap ${KEYSTONE_LIB_EAPP})

# SlotTEE runtime slot-policy syscall probe.
add_executable(test-lt-user-policy lt-user-policy/lt-user-policy.c)
target_link_libraries(test-lt-user-policy ${KEYSTONE_LIB_EAPP})

# SlotTEE watchdog TTL probe: RT-authorized short lease for host-side expiry.
add_executable(test-lt-user-watchdog-ttl
  lt-user-watchdog-ttl/lt-user-watchdog-ttl.c)
target_link_libraries(test-lt-user-watchdog-ttl ${KEYSTONE_LIB_EAPP})

# SlotTEE paper-evaluation eapp: RT-authorized cap mint/export plus OCALL reentry.
add_executable(test-lt-user-paper-eval lt-user-paper-eval/lt-user-paper-eval.c)
target_link_libraries(test-lt-user-paper-eval ${KEYSTONE_LIB_EAPP})

# SlotTEE Phase 37 multihart LT ticket demo.
add_executable(test-lt-user-multihart-ticket
  lt-user-multihart-ticket/lt-user-multihart-ticket.c)
target_link_libraries(test-lt-user-multihart-ticket ${KEYSTONE_LIB_EAPP})

# SlotTEE LT-aware U-mode fault probes. These are packaged for explicit
# wrappers only; the default full tests.ke run must not intentionally fault.
add_executable(test-lt-user-illegal lt-user-illegal/lt-user-illegal.c)
target_link_libraries(test-lt-user-illegal ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-page-fault lt-user-page-fault/lt-user-page-fault.c)
target_link_libraries(test-lt-user-page-fault ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-illegal-cleanup lt-user-illegal-cleanup/lt-user-illegal-cleanup.c)
target_link_libraries(test-lt-user-illegal-cleanup ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-page-fault-cleanup lt-user-page-fault-cleanup/lt-user-page-fault-cleanup.c)
target_link_libraries(test-lt-user-page-fault-cleanup ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-busy-revoke lt-user-busy-revoke/lt-user-busy-revoke.c)
target_link_libraries(test-lt-user-busy-revoke ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-first-busy-revoke lt-user-first-busy-revoke/lt-user-first-busy-revoke.c)
target_link_libraries(test-lt-user-first-busy-revoke ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-edgecall-stress
  lt-user-edgecall-stress/lt-user-edgecall-stress.c)
target_link_libraries(test-lt-user-edgecall-stress ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-timer-preempt
  lt-user-timer-preempt/lt-user-timer-preempt.c)
target_link_libraries(test-lt-user-timer-preempt ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-preempt-sched
  lt-user-preempt-sched/lt-user-preempt-sched.c)
target_link_libraries(test-lt-user-preempt-sched ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-preempt-multihart
  lt-user-preempt-multihart/lt-user-preempt-multihart.c)
target_link_libraries(test-lt-user-preempt-multihart ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-preempt-steal
  lt-user-preempt-steal/lt-user-preempt-steal.c)
target_link_libraries(test-lt-user-preempt-steal ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-preempt-bestvictim
  lt-user-preempt-bestvictim/lt-user-preempt-bestvictim.c)
target_link_libraries(test-lt-user-preempt-bestvictim ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-ledger
  lt-user-ledger/lt-user-ledger.c)
target_link_libraries(test-lt-user-ledger ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-matmul
  lt-user-matmul/lt-user-matmul.c)
target_link_libraries(test-lt-user-matmul ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-lu
  lt-user-lu/lt-user-lu.c)
target_link_libraries(test-lt-user-lu ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-fft
  lt-user-fft/lt-user-fft.c)
target_link_libraries(test-lt-user-fft ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-radix
  lt-user-radix/lt-user-radix.c)
target_link_libraries(test-lt-user-radix ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-mlp
  lt-user-mlp/lt-user-mlp.c)
target_link_libraries(test-lt-user-mlp ${KEYSTONE_LIB_EAPP})

add_executable(test-lt-user-revoke-ipi
  lt-user-revoke-ipi/lt-user-revoke-ipi.c)
target_link_libraries(test-lt-user-revoke-ipi ${KEYSTONE_LIB_EAPP})

###############################################
# a script for running all test enclaves
set(test_script_tmp ${CMAKE_CURRENT_BINARY_DIR}/tmp/run-test.sh)
set(test_script ${CMAKE_CURRENT_BINARY_DIR}/run-test.sh)

file(WRITE ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-stub\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-stub\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-real\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-real\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-negative\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-negative\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lease\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-lease\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-destroy-recreate\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-destroy-recreate\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-epoch\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-epoch\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-multislot\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-multislot\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-capability\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-capability\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-revoke-replay\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-revoke-replay\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-bench\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-bench\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-pthread-pool\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-pthread-pool\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-scheduler\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-paper-eval eyrie-rt loader.bin --load-only --enter-slot-lt-scheduler\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-context\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-paper-eval eyrie-rt loader.bin --load-only --enter-slot-lt-context\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-yield\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-paper-eval eyrie-rt loader.bin --load-only --enter-slot-lt-yield\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-bind\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-lt-bind\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-trap-safe\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-lt-trap-safe\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-ecall\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-lt-ecall\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-lt-user\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-same-enclave-multislot\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --enter-slot-same-enclave-multislot\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-ocall\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-lt-user-ocall\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-ocall-same-enclave\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-lt-user-ocall-same-enclave\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-illegal\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-illegal eyrie-rt loader.bin --load-only --enter-slot-lt-user-illegal\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-illegal-cleanup-same-enclave\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-illegal-cleanup eyrie-rt loader.bin --load-only --enter-slot-lt-user-illegal-cleanup-same-enclave\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-page-fault\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-page-fault eyrie-rt loader.bin --load-only --enter-slot-lt-user-page-fault\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-page-fault-cleanup-same-enclave\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-page-fault-cleanup eyrie-rt loader.bin --load-only --enter-slot-lt-user-page-fault-cleanup-same-enclave\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-destroy-after-reentry\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-lt-user-destroy-after-reentry\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-revoke-after-reentry\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-lt-user-revoke-after-reentry\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lt-user-destroy-race\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-lt-user-destroy-race\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-double-enter-epoch-rollover\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-double-enter-epoch-rollover\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-mark-revoke\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-mark-revoke\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-active-revoke-boundary\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-active-revoke-boundary\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-active-revoke-timer-stress\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-active-revoke-timer-stress\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-first-active-revoke-template\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-first-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-first-active-revoke-template\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-first-active-revoke-diagnostic\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-first-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-first-active-revoke-diagnostic\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-active-revoke-destroy-race\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-first-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-active-revoke-destroy-race\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-active-revoke-multislot-stress\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-first-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-active-revoke-multislot-stress\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-rt-revoke-fault\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-page-fault-cleanup eyrie-rt loader.bin --load-only --enter-slot-rt-revoke-fault\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-revoke-stress\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-revoke-stress\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-cap-mac-forge\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-cap-mac-forge\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-cap-generation-replay\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ocall eyrie-rt loader.bin --load-only --enter-slot-cap-generation-replay\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-rt-authorized-mint\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-mint-cap eyrie-rt loader.bin --enter-slot-rt-authorized-mint\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-policy\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-policy eyrie-rt loader.bin --enter-slot-policy\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-watchdog-ttl\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-watchdog-ttl eyrie-rt loader.bin --enter-slot-watchdog-ttl\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-debug-mint-gate\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-stack eyrie-rt loader.bin --load-only --slottee-debug-mint-gate\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-paper-eval\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-paper-eval eyrie-rt loader.bin --slottee-paper-eval\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-ticket-demo\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-paper-eval eyrie-rt loader.bin --slottee-ticket-demo\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-multihart-ticket\" ]; then\n")
file(APPEND ${test_script_tmp} "  shift\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-multihart-ticket eyrie-rt loader.bin --slottee-multihart-ticket \"$@\"\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-multihart-ticket-max\" ]; then\n")
file(APPEND ${test_script_tmp} "  shift\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-multihart-ticket eyrie-rt loader.bin --slottee-multihart-ticket-max \"$@\"\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-edgecall-interference-stress\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-edgecall-stress eyrie-rt loader.bin --slottee-edgecall-interference-stress\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-timer-preempt\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-timer-preempt eyrie-rt loader.bin --enter-slot-timer-preempt\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-preempt-sched\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-preempt-sched eyrie-rt loader.bin --enter-slot-preempt-sched\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-preempt-multihart\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-preempt-multihart eyrie-rt loader.bin --enter-slot-preempt-multihart\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-preempt-steal\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-preempt-steal eyrie-rt loader.bin --enter-slot-preempt-steal\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-preempt-bestvictim\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-preempt-bestvictim eyrie-rt loader.bin --enter-slot-preempt-bestvictim\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-ledger\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-ledger eyrie-rt loader.bin --enter-slot-ledger\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-matmul\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-matmul eyrie-rt loader.bin --enter-slot-matmul\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-lu\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-lu eyrie-rt loader.bin --enter-slot-lu\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-fft eyrie-rt loader.bin --enter-slot-fft\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-radix eyrie-rt loader.bin --enter-slot-radix\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-mlp eyrie-rt loader.bin --enter-slot-mlp\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--enter-slot-revoke-ipi\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-revoke-ipi eyrie-rt loader.bin --enter-slot-revoke-ipi\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-host-dos-stress\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-multihart-ticket eyrie-rt loader.bin --slottee-host-dos-stress\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-multihart-stress\" ]; then\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-multihart-ticket eyrie-rt loader.bin --slottee-multihart-stress || exit $?\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-edgecall-stress eyrie-rt loader.bin --slottee-edgecall-interference-stress || exit $?\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-multihart-ticket eyrie-rt loader.bin --slottee-host-dos-stress || exit $?\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-active-revoke-timer-stress || exit $?\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-first-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-active-revoke-destroy-race || exit $?\n")
file(APPEND ${test_script_tmp} "  ./test-runner test-lt-user-first-busy-revoke eyrie-rt loader.bin --load-only --enter-slot-active-revoke-multislot-stress\n")
file(APPEND ${test_script_tmp} "  exit $?\n")
file(APPEND ${test_script_tmp} "fi\n")
file(APPEND ${test_script_tmp} "if [ \"$1\" = \"--slottee-dmesg-audit\" ]; then\n")
file(APPEND ${test_script_tmp} "  dmesg | tail -180 | tee /tmp/slottee-dmesg-tail.log\n")
file(APPEND ${test_script_tmp} "  if grep -E -i \"rcu.*stall|kernel panic|oops|BUG:\" /tmp/slottee-dmesg-tail.log; then\n")
file(APPEND ${test_script_tmp} "    echo \"[FAIL] slottee dmesg audit found kernel warning\"\n")
file(APPEND ${test_script_tmp} "    exit 1\n")
file(APPEND ${test_script_tmp} "  fi\n")
file(APPEND ${test_script_tmp} "  echo \"[slottee] dmesg_audit ok=1\"\n")
file(APPEND ${test_script_tmp} "  exit 0\n")
file(APPEND ${test_script_tmp} "fi\n")
foreach (test IN ITEMS ${all_test_bins})
  file(APPEND ${test_script_tmp} "echo 'testing ${test}'\n")
  if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${test}/retval)
    execute_process(COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/${test}/retval OUTPUT_VARIABLE retval)
    file(APPEND ${test_script_tmp} "./${host_bin} ${test} eyrie-rt loader.bin --retval ${retval}")
  else()
    file(APPEND ${test_script_tmp} "./${host_bin} ${test} eyrie-rt loader.bin\n")
  endif()
endforeach(test)

file(COPY ${test_script_tmp} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
  FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/tmp)

# linker flags for all tests
set_target_properties(${all_test_bins} ${slottee_fault_test_bins}
  ${slottee_explicit_test_bins} ${slottee_stress_test_bins}
  PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")
###############################################

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER} pthread)

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(test-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(test-package
  ${package_name}
  ${package_script}
  ${test_script} ${eyrie_files_to_copy} ${all_test_bins} ${slottee_fault_test_bins}
  ${slottee_explicit_test_bins} ${slottee_stress_test_bins} ${host_bin}
  )

add_dependencies(test-package test-eyrie)

# add package to the top-level target
add_dependencies(examples test-package)
