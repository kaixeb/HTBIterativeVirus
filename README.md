# HTBIterativeVirus
## Decryptor for "Iterative Virus" challenge from HTB
This python script extracts encrypted content from the provided binary (iterative_virus.exe), decrypts the data using keys, which were found by reverse engineering the binary, then patches the PE with decrypted data and saves it as a new binary called "iterative_virus_decrypted.exe". After that, by using whichever disassembler/decompiler you prefer, you can find the flag in clear text.
