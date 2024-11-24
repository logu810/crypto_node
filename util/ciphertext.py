"""A module to keep track of a ciphertext."""

class Ciphertext:

    """An instance of a ciphertext.

    This is a wrapper class for a ciphertext, which consists
    of two polynomial.

    Attributes:
        c0 (Polynomial): First element of ciphertext.
        c1 (Polynomial): Second element of ciphertext.
        scaling_factor (float): Scaling factor.
        modulus (int): Ciphertext modulus.
    """

    def __init__(self, c0, c1, scaling_factor=1 << 30, modulus=1 << 600):
        """Sets ciphertext to given polynomials.

        Args:
            c0 (Polynomial): First element of ciphertext.
            c1 (Polynomial): Second element of ciphertext.
            scaling_factor (float): Scaling factor. Can be None for BFV.
            modulus (int): Ciphertext modulus. Can be None for BFV.
        """
        self.c0 = c0
        self.c1 = c1
        self.scaling_factor = scaling_factor
        self.modulus = modulus

    def to_dict(self):
        return {
            "c0": str(self.c0),  # Assuming p0 is serializable or has __str__ method
            "c1": str(self.c1)   # Assuming p1 is serializable or has __str__ method
        }

    def __str__(self):
        """Represents Ciphertext as a string.

        Returns:
            A string which represents the Ciphertext.
        """
        return 'c0: ' + str(self.c0) + '\n + c1: ' + str(self.c1)
