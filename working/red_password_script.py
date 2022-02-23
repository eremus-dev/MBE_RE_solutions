from ctypes import c_uint
"""
void red(void)
{
  int local_c;

  red_preflight();
  local_c = 0;
  while( true ) {
    if (0x12 < local_c) {
      wire_red = 0;
      return;
    }
    if (buffer[local_c] != "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[r[2] & 0x1f]) break;
    r[2] = r[1] << 0x1b | (uint)r[2] >> 5;
    r[1] = r[0] << 0x1b | (uint)r[1] >> 5;
    r[0] = (uint)r[0] >> 5;
    local_c = local_c + 1;
  }
  wire_red = wire_red + 1;
  return;
}"""
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
