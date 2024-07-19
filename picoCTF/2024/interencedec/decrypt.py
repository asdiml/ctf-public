import base64

f = open('enc_flag', 'r')
first_dec = base64.b64decode(f.read()).decode()
second_dec = base64.b64decode(first_dec[2:-2]).decode()
m = ''.join([(chr(ord(shifted) + 26) 
    if (shifted := chr(ord(c)-(ord(second_dec[0])-ord('p')))) and (c.isupper() and ord(shifted) < ord('A') or c.islower() and ord(shifted) < ord('a')) else shifted)
    if c.isalpha() else c for c in second_dec])
print(m)