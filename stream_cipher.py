import binascii

global sesh_key
sesh_key = ''
def user_text(input_msg):
  plaintext = input_msg
  print ("plaintText is :")
  print plaintext
  string_to_binary(plaintext)

def string_to_binary(user_text):
  binary_list = [ bin(ord(ch))[2:].zfill(8) for ch in user_text ] #in list form
  encryption_box(binary_list)

def xor_key(key):
  global sesh_key
  sesh_key = key

def encryption_box(binary_list, hkey = None):
  key = sesh_key
  ct_blist = []
  ct_dec = []
  ct = []
  for i in range(len(binary_list)):
    xor_key_blist = int(binary_list[i], 2)^int(key, 2) #xored
    encrypting = bin(xor_key_blist)[2:].zfill(len(binary_list[1]))    #xored encryption
    ct_blist.append(encrypting)
  print("cipher text : ")
  print ''.join(ct_blist)

