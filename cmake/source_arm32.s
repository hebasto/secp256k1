.syntax unified
.eabi_attribute 24, 1
.eabi_attribute 25, 1
.text
.global	test_function
.type	test_function, %function
test_function:
	ldr	r0, =0x002A
	bx	lr
