/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017 The University of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


.syntax unified

.global btrace_save_regs
.func
.type btrace_save_regs, %function

.thumb_func
btrace_save_regs:
  // Register save
  PUSH {R3}

  // Get previous LR
  LDR R3, [SP, #16]

  STR LR, [R1] // CALLER PC
  STR R3, [R1, #4]
  STR SP, [R1, #8]

  POP {R3}

  BX LR

.endfunc

.global btrace_branch_hook
.func
.type btrace_branch_hook, %function

.thumb_func
btrace_branch_hook:
  // Store stack pointer
  PUSH {LR}

  /* Before we ruin anything, save R2 */
  STR R2, [R0, #16]

  /* Continue SP backup */
  ADD R2, R2, #12

  /* Set SP */
  STR R2, [R0, #4]

  /* Special care for R14 / LR */
  STR R1, [R0, #64]

  /* Restore R1 from stack*/
  LDR R1, [R2]

  /* General Purpose Registers */
  STR R1, [R0, #12]

  // R2 already there
  STR R3, [R0, #20]
  STR R4, [R0, #24]
  STR R5, [R0, #28]
  STR R6, [R0, #32]
  STR R7, [R0, #36]
  STR R8, [R0, #40]
  STR R8, [R0, #44]
  STR R10, [R0, #48]
  STR R11, [R0, #52]
  STR R12, [R0, #56]
  STR R13, [R0, #60]

  // That should (??) Get LR
  LDR R2, [SP]
  STR R2, [R0, #68]

  LDR R2, =btrace_branch_hook_c
  BLX R2
  CBNZ R0, err_trace

  POP {LR}
  BX LR

.endfunc

.global btrace_return_hook
.func
.type btrace_return_hook, %function

.thumb_func
btrace_return_hook:
  // Store stack pointer
  PUSH {LR}

  /* Before we ruin anything, save R2 */
  // STR R2, [R0, #16]

  /* Continue SP backup */
  ADD R2, R2, #12

  /* Set SP */
  STR R2, [R0, #4]

  /* Special care for R14 / LR */
  STR R1, [R0, #64]

  /* Restore R1 from stack*/
  LDR R1, [R2]

  /* General Purpose Registers */
  STR R1, [R0, #12]

  // R2 already there
  STR R3, [R0, #20]
  STR R4, [R0, #24]
  STR R5, [R0, #28]
  STR R6, [R0, #32]
  STR R7, [R0, #36]
  STR R8, [R0, #40]
  STR R8, [R0, #44]
  STR R10, [R0, #48]
  STR R11, [R0, #52]
  STR R12, [R0, #56]
  STR R13, [R0, #60]

  // That should (??) Get LR
  LDR R2, [SP, #8]
  STR R2, [R0, #68]

  LDR R2, =btrace_return_hook_c
  BLX R2
  CBNZ R0, err_trace

/*
  // Stack print
  MOV R0, SP
  LDR R2, =stack_print
  BLX R2
*/

  POP {LR}
  BX LR

err_trace:
  LDR R2, =btrace_error
  BLX R2

.endfunc
