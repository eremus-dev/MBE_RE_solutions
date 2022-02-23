alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
r0 = 1804289383
r1 = 846930886
r2 = 1681692777

password = []
for i in range(0, 0x13):
    temp_index = r2 & 0x1f
    password.append(alpha[temp_index])
    r2 = r1 << 0x1b | r2 >> 5
    r1 = r0 << 0x1b | r1 >> 5
    r0 = r0 >> 5

print(''.join(password))
