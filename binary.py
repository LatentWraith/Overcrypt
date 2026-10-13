import secrets
from typing import cast

class Block():
    def __init__(self, vocab_size: int):
        self.mapping = None
        self.reverse_map = None
        self.deltas = None
        
        self.warp = vocab_size
        
    def register_key(self, mapping: list[int], deltas: list[int]):
        assert deltas[0]<self.warp and deltas[1]<self.warp and deltas[2]<self.warp and deltas[3]<self.warp
        assert len(mapping)==self.warp
        
        reverse_map = [0 for _ in range(self.warp)]
        for idx, m in enumerate(mapping):
            reverse_map[m] = idx
        
        self.mapping = mapping
        self.reverse_map = reverse_map
        self.deltas = deltas
        
    def generate_key(self):
        buff = [x for x in range(0, self.warp)]
        
        key = []
        for _ in range(self.warp):
            i = secrets.randbelow(len(buff))
            key.append(buff[i])

            buff.remove(buff[i])
    
        delta = [secrets.randbelow(self.warp-2) + 2]
        delta.append(secrets.randbelow(self.warp-2) + 2)
        delta.append(secrets.randbelow(self.warp-2) + 2)
        delta.append(secrets.randbelow(self.warp-2) + 2)
        
        self.register_key(key, delta)

    def encrypt(self, raw: bytes) -> bytes:
        assert self.mapping is not None and self.deltas is not None
        
        out = bytearray()
        last_char = 0
        for idx, x in enumerate(raw):
            shift = (pow(idx, self.deltas[0], self.warp) + self.deltas[1] * (idx % self.warp) + self.deltas[2] + (self.deltas[3] * last_char)) % self.warp
            mapped = self.mapping[(x+shift)%self.warp]
            
            last_char = mapped
            out.append(mapped)

        return bytes(out)

    def decrypt(self, enc: bytes) -> bytes:
        assert self.mapping is not None and self.deltas is not None and self.reverse_map is not None
        
        out = bytearray()
        last_char = 0
        for idx, x in enumerate(enc):
            mapped = self.reverse_map[x]
            shift = (pow(idx, self.deltas[0], self.warp) + self.deltas[1] * (idx % self.warp) + self.deltas[2] + (self.deltas[3] * last_char)) % self.warp
            shifted = (mapped-shift)%self.warp
            
            last_char = x
            out.append(shifted)

        return bytes(out)
    
class OvercryptBinary():
    """
    ## Usage:
    
    ```
    ovc = OvercryptBinary(layers = 8)
    
    enc = ovc.encrypt(binary_data)
    
    dec = ovc.decrypt(enc)
    ```
    
    
    ## Exporting Keys:
    
    ```
    ovc = OvercryptBinary(layers = 8)
    
    keys = ovc.state_dict()
    ```
    
    
    ## Loading Keys:
    
    ```
    ovc = OvercryptBinary(layers = 8)
    
    ovc.load_state_dict(keys)
    ```
    """
    def __init__(self, layers: int = 8, auto_init: bool = True):
        """Initialise an Overcrypt Instance

        Args:
            layers (int, optional): Number of Shift-Substitute layers. Defaults to 8.
            auto_init (bool, optional): Whether to generate keys automatically. Defaults to True.
        """
        self.V = "1.0.0"
        self.vocab_size = 256
        
        self.layer_n = layers
        self.blocks = [Block(self.vocab_size) for _ in range(layers)]
        if auto_init:
            for b in self.blocks:
                b.generate_key()
                
    def state_dict(self) -> dict:
        out = {}
        out["version"] = self.V
        out["layers"] = self.layer_n

        for idx, b in enumerate(self.blocks):
            out[f"b{idx}"] = {"key": b.mapping, "deltas": b.deltas}
            
        return out
    
    def load_state_dict(self, state: dict):
        assert self.V == state["version"], f"Overcrypt version does not match: expected {self.V}, got {state['version']}"
        assert self.layer_n == state["layers"], f"Layer count does not match: expected {self.layer_n}, got {state['layers']}"
        for idx, b in enumerate(self.blocks):
            sub = cast(dict, state.get(f"b{idx}"))
            b.register_key(sub["key"], sub["deltas"])
        
    def encrypt(self, x: bytes) -> bytes:
        iv = secrets.token_bytes(4)
        x = iv + x
        
        for b in self.blocks:
            x = b.encrypt(x)
            
        return x

    def decrypt(self, x: bytes) -> bytes:
        for idx in range(self.layer_n-1, -1, -1):
            x = self.blocks[idx].decrypt(x)
        
        x = x[4:]
        return x