#[derive(Clone)]
pub struct BigInt {
    pub value: Vec<u8>,
}

impl BigInt {
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        let mut result = Self::new(vec![1]);
        let mut base = self.mod_(modulus);
    
        for byte in &exp.value {
            for i in (0..8).rev() {
                result = result.mul_mod(&result, modulus);  // Square
                if (byte >> i) & 1 == 1 {
                    result = result.mul_mod(&base, modulus);  // Multiply
                }
            }
        }
    
        result
    }    

    pub fn mul_mod(&self, other: &Self, modulus: &Self) -> Self {
        let product = self.mul(other);
        product.mod_(&modulus)
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut value = vec![0; self.value.len() + other.value.len()];
        for i in (0..self.value.len()).rev() {
            let mut carry: u16 = 0;
            for j in (0..other.value.len()).rev() {
                let ai = self.value[i] as u16;
                let bj = other.value[j] as u16;
                let ri = i + j + 1;

                let tmp = value[ri] as u16 + ai * bj + carry;
                value[ri] = (tmp & 0xff) as u8;
                carry = tmp >> 8;
            }
            value[i] += carry as u8;
        }

        while value.len() > 1 && value[0] == 0 {
            value.remove(0);
        }

        Self { value }
    }

    pub fn mod_(&self, modulus: &Self) -> Self {
        let (_, remainder) = self.div(modulus);
        remainder
    }

    pub fn sub(&self, other: &Self) -> Self {
        assert!(self.cmp(other) >= 0, "Subtraction would result in negative");
        let mut result = vec![0u8; self.value.len()];
        let mut borrow = 0i16;
    
        let offset = self.value.len().saturating_sub(other.value.len());
        for i in (0..self.value.len()).rev() {
            let a = self.value[i] as i16;
            let b = if i >= offset { other.value[i - offset] as i16 } else { 0 };
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = diff as u8;
        }
    
        while result.len() > 1 && result[0] == 0 {
            result.remove(0);
        }
    
        Self::new(result)
    }
    

    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.value.len().max(other.value.len());
        let mut result = vec![0u8; max_len + 1];
        let mut carry = 0u16;
    
        for i in 0..max_len {
            let a = *self.value.get(self.value.len().wrapping_sub(1).wrapping_sub(i)).unwrap_or(&0) as u16;
            let b = *other.value.get(other.value.len().wrapping_sub(1).wrapping_sub(i)).unwrap_or(&0) as u16;
            let sum = a + b + carry;
            result[max_len - i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }
    
        result[0] = carry as u8;
        while result.len() > 1 && result[0] == 0 {
            result.remove(0);
        }
    
        Self { value: result }
    }

    pub fn complement(&self) -> Self {
        let mut value = self.value.clone();
        for i in 0..value.len() {
            value[i] = !value[i];
        }
        Self { value }
    }

    pub fn cmp(&self, other: &Self) -> i8 {
        if self.value.len() > other.value.len() {
            return 1;
        }
        if self.value.len() < other.value.len() {
            return -1;
        }
        
        for i in 0..self.value.len() {
            if self.value[i] > other.value[i] { return 1; }
            if self.value[i] < other.value[i] { return -1; }
        }
        0
    }

    pub fn shl1(a: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; a.len() + 1];
        let mut carry = 0u8;
        for i in (0..a.len()).rev() {
            let shifted = (a[i] << 1) | carry;
            carry = (a[i] & 0x80) >> 7;
            result[i + 1] = shifted;
        }
        result[0] = carry;
        while result.len() > 1 && result[0] == 0 {
            result.remove(0);
        }
        result
    }

    pub fn shr1(a: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; a.len()];
        let mut carry = 0u8;
        for i in 0..a.len() {
            let shifted = (a[i] >> 1) | (carry << 7);
            carry = a[i] & 1;
            result[i] = shifted;
        }
        while result.len() > 1 && result[0] == 0 {
            result.remove(0);
        }
        result
    }

    pub fn div(&self, other: &Self) -> (Self, Self) {
        assert!(!other.value.is_empty(), "Division by zero");

        let mut quotient = vec![0u8; self.value.len()];
        let mut remainder = Self::new(vec![0u8]);
        remainder.value.reserve(self.value.len());

        for bit in 0..(self.value.len() * 8) {
            remainder = BigInt::new(Self::shl1(&remainder.value));
            
            let byte_index = bit / 8;
            let bit_index = 7 - (bit % 8);
            let bit_val = (self.value[byte_index] >> bit_index) & 1;

            if remainder.value.is_empty() {
                remainder.value.push(bit_val);
            } else {
                let last = remainder.value.len() - 1;
                remainder.value[last] |= bit_val;
            }

            if remainder.cmp(other) >= 0 {
                remainder = remainder.sub(other);
                quotient[byte_index] |= 1 << bit_index;
            }
        }

        (BigInt::new(quotient), remainder)
    }

}