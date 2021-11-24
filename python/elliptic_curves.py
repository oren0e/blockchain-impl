"""
An example output for this program:

0x1d21db3051562f89cb530bef6d95ef35ed46c8ca80f27fd35dbc4762a093cc44
0xe467c2a2be289ca49ae51cedfb7cdb735d7f58245b880733c8e32f732729e99f
Concatenated x and y Public Key:  0xfb974da21c0a5d0606dd75b1e44bcc54df398338a48950f98dcf6e0df5a77bed0c9b0b4083a445a4161d749033ba694bd33644068e010733c8e32f732729e99f
Keccak256 Hash:  d1eb62423b97335a5a375117ab62c032365b357cdfd1e1f3d7b2217535b90318
Ethereum Address:  0xab62c032365b357cdfd1e1f3d7b2217535b90318

Notice how the last 20 bytes of the Keccak256 hash is the ethereum address
"""
from Crypto.Hash import keccak
from fastecdsa import keys, curve
if __name__ == "__main__":
    private_key, public_key = keys.gen_keypair(curve.P256)

    # let's create the public key by hand
    public_key_manual = curve.P256.G * private_key  # elliptic-curve multiplication
    assert public_key == public_key_manual
    print(hex(public_key.x))
    print(hex(public_key.y))

    # Creating an Ethereum address
    # construct the public key by concatinating the x and y coordinates
    public_key_for_address = hex(int(str(public_key.x) + str(public_key.y)))
    print("Concatenated x and y Public Key: ", public_key_for_address)
    # Run it through a Keccak256 hash function
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(str.encode(public_key_for_address))
    print("Keccak256 Hash: ", keccak_hash.hexdigest())
    # To get the address keep the last 20 bytes only
    hex_string = str.encode(keccak_hash.hexdigest())[-40:].decode()
    eth_address = hex(int(hex_string, 16))
    print("Ethereum Address: ", eth_address)
