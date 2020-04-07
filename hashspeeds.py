import numpy as np
import matplotlib.pyplot as plt

# hash speed in H/s
HASH_SPEED = 1105 * (10**6)
min_length = 6
max_length = 12

symbols = " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
password_length = [i for i in range(min_length, max_length+1)]

lowercase = [0 for i in range(max_length - min_length + 1)]
letters = [0 for i in range(max_length - min_length + 1)]
letters_digits = [0 for i in range(max_length - min_length + 1)]
letters_digits_symbols = [0 for i in range(max_length - min_length + 1)]


#compute the time needed in hours
for i,l in enumerate(password_length):
    lowercase[i] = 26**l / HASH_SPEED / 3600 /24
    letters[i] = (26+26)**l / HASH_SPEED / 3600 /24
    letters_digits[i] = ((26+26+10)**l) / HASH_SPEED / 3600 /24
    letters_digits_symbols[i] = (26+26+10+len(symbols))**l / HASH_SPEED / 3600/24


plt.figure("Hash speeds", figsize=(12,8))
# plt.title("Time required to test every password at {}MH".format(int(HASH_SPEED/(10**6))))
plt.xlabel("Password length")
plt.ylabel("Time (in days)")
plt.plot(password_length, letters, ".--",label="letters")
plt.plot(password_length, letters_digits, ".--", label="letters and digits")
plt.plot(password_length, letters_digits_symbols,".--", label="letters, digits and symbols")
plt.legend()
plt.yscale("symlog")
plt.ylim(bottom=-0.5)

locs = [1,10,100,365,3650,36500]
labels = ["1","10","100","1 year", "10 years", "100 years"]
plt.yticks(locs, labels)

plt.savefig("hashcat_speeds.png")
plt.show()