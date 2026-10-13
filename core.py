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

    def encrypt(self, raw: list[int]) -> list[int]:
        assert self.mapping is not None and self.deltas is not None
        
        last_char = 0
        for idx, x in enumerate(raw):
            shift = (pow(idx, self.deltas[0], self.warp) + self.deltas[1] * (idx % self.warp) + self.deltas[2] + (self.deltas[3] * last_char)) % self.warp
            mapped = self.mapping[(x+shift)%self.warp]
            
            last_char = mapped
            raw[idx] = mapped

        return raw

    def decrypt(self, enc: list[int]) -> list[int]:
        assert self.mapping is not None and self.deltas is not None and self.reverse_map is not None
        
        last_char = 0
        for idx, x in enumerate(enc):
            mapped = self.reverse_map[x]
            shift = (pow(idx, self.deltas[0], self.warp) + self.deltas[1] * (idx % self.warp) + self.deltas[2] + (self.deltas[3] * last_char)) % self.warp
            shifted = (mapped-shift)%self.warp
            
            last_char = x
            enc[idx] = shifted

        return enc
    
class Overcrypt():
    """
    ## Usage:
    
    ```
    ovc = Overcrypt(alpha = True, num = True, special = True, layers = 8)
    
    enc = ovc.encrypt(data)
    
    dec = ovc.decrypt(enc)
    ```
    
    
    ## Exporting Keys:
    
    ```
    ovc = Overcrypt(alpha = True, num = True, special = True, layers = 8)
    
    keys = ovc.state_dict()
    ```
    
    
    ## Loading Keys:
    
    ```
    ovc = Overcrypt(alpha = True, num = True, special = True, layers = 8)
    
    ovc.load_state_dict(keys)
    ```
    """
    def __init__(self, alpha: bool, num: bool, special: bool, new_line: bool = True, layers: int = 8, auto_init: bool = True, custom: list = []):
        """Initialise an Overcrypt Instance

        Args:
            alpha (bool): Whether to include Alphabetical Characters in the Vocabulary
            num (bool): Whether to include Numeric Characters in the Vocabulary
            special (bool): Whether to include Special Characters in the Vocabulary
            new_line (bool, optional): Whether to include "\\n" in the Vocabulary
            layers (int, optional): Number of Shift-Substitute layers. Defaults to 8.
            auto_init (bool, optional): Whether to generate keys automatically. Defaults to True.
            custom (list, optional): Custom Characters to add to the vocabulary. Defaults to [].
        """
        self.V = "1.0.0"
        
        vocab = ["\n"] if new_line else []
        vocab.extend(custom)
        
        if num:
            vocab.extend([str(x) for x in range(10)])
        if alpha:
            vocab.extend([chr(x) for x in range(ord("A"), ord("Z") + 1)])
            vocab.extend([chr(x) for x in range(ord("a"), ord("z") + 1)])
        if special:
            vocab.extend([chr(x) for x in range(ord(" "), ord("/") + 1)])
            vocab.extend([chr(x) for x in range(ord(":"), ord("@") + 1)])
            vocab.extend([chr(x) for x in range(ord("["), 96 + 1)])
            vocab.extend([chr(x) for x in range(ord("{"), ord("~") + 1)])
        self.to_char = vocab
        self.to_idx = {}
        for idx, x in enumerate(vocab):
            self.to_idx[x] = idx
        self.layer_n = layers
        
        self.vocab_size = len(vocab)
        self.blocks = [Block(self.vocab_size) for _ in range(layers)]
        if auto_init:
            for b in self.blocks:
                b.generate_key()
                
    def state_dict(self, save_vocab: bool = False) -> dict:
        out = {}
        out["version"] = self.V
        out["vocab_size"] = self.vocab_size
        out["layers"] = self.layer_n
        
        if save_vocab: out["vocab"] = self.to_char
        
        for idx, b in enumerate(self.blocks):
            out[f"b{idx}"] = {"key": b.mapping, "deltas": b.deltas}
            
        return out
    
    def load_state_dict(self, state: dict):
        assert state["version"] == self.V, f"Overcrypt version does not match: expected {self.V}, got {state['version']}"
        assert state["vocab_size"] == self.vocab_size, f"Vocabulary size does not match: expected {self.vocab_size}, got {state['vocab_size']}"
        assert state["layers"] == self.layer_n, f"Layer count does not match: expected {self.layer_n}, got {state['layers']}"
        if "vocab" in state.keys():
            self.to_char = state["vocab"]
            self.to_idx = {}
            for idx, x in enumerate(self.to_char):
                self.to_idx[x] = idx
            
        for idx, b in enumerate(self.blocks):
            sub = cast(dict, state.get(f"b{idx}"))
            b.register_key(sub["key"], sub["deltas"])
        
    def encrypt(self, pt: str) -> str:
        iv0 = secrets.randbelow(self.vocab_size)
        iv1 = secrets.randbelow(self.vocab_size)
        iv2 = secrets.randbelow(self.vocab_size)
        iv3 = secrets.randbelow(self.vocab_size)
        
        x = [iv0, iv1, iv2, iv3]
        for char in pt:
            x.append(self.to_idx[char])
            
        for b in self.blocks:
            x = b.encrypt(x)
        
        out = ""
        for i in x:
            out+=self.to_char[i]
        return out

    def decrypt(self, enc: str) -> str:
        x = []
        for char in enc:
                    x.append(self.to_idx[char])
                    
        for idx in range(self.layer_n-1, -1, -1):
            x = self.blocks[idx].decrypt(x)
        
        x = x[4:]
        out = ""
        for i in x:
            out+=self.to_char[i]
        return out