## Format String Arbitrary Write

### Writing a Value mod Size Storable in x Bytes

If the number of characters already printed by `printf` is more than what can be stored in a byte e.g. `%1888c%48hhn...`, then only what can fit into a byte will be written by taking the remainder (mod the maximum value storable in one byte). 

In the example given, `1888 = 0x760`, so the byte at address given by the 48th `hhn` argument on the variable argument list will be overwritten by the value 0x60. 

### Writing a Value that is Negative in Signed Interpretation

While the [`printf` docs](https://cplusplus.com/reference/cstdio/printf/) mentions that the pointer provided as the argument referenced `%n` should be to a signed integer/short/char/etc, it is ok to provide a number of characters that would technically overflow that signed integer/short/char/etc to become a negative value. 

Therefore when using a format specifier like `%hhn`, it is ok to write 223 characters so that the byte will be overwritten with the byte value `0xdf`. 