# Messages in SSH RSA keys

## Motivation
I thought it'd be amusing to have a public SSH RSA key that contains a readable 
message and not only random-looking ASCII, if only to confuse the next guy putting his 
key on some machine at work...

## Prerequisites
Requires the pyasn1 module. Install with ```pip install pyasn1```

## How to use it
Let's create a vanilla unencrypted (no passphrase) [RSA](http://en.wikipedia.org/wiki/RSA) 
key pair for SSH:

    ssh-keygen -t rsa -b 1024
    Generating public/private rsa key pair.
    Enter file in which to save the key: vanilla
    Enter passphrase (empty for no passphrase): 
    Enter same passphrase again: 
    Your identification has been saved in vanilla.
    Your public key has been saved in vanilla.pub.
    The key fingerprint is:
    29:64:0c:5d:01:fd:f4:f7:99:a9:16:b8:8b:a3:e9:0c thi@tyr
    The key's randomart image is:
    +--[ RSA 1024]----+
    |    ...+o.       |
    |     o. . .      |
    |      +  o .     |
    |     o   .. . .  |
    |      . S   .. .+|
    |       .   . . +.|
    |     E      . o  |
    |      o .... o   |
    |      .=....o    |
    +-----------------+
    
Splendid. Now we have the files ''vanilla'' and ''vanilla.pub'', which contain the 
private and public keys respectively. This particular public key looks like this:

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDJaX+dfSdydMbnJrEqTipwajK8qQzKoNMXt0NAHKqeKyi+3zLEO
    yhB+bVAEOUcQtkDPz5aYqk/wrF+ht+mt1i80wtGCgifGvJgzZqNcRh/p7F3g9OXFzaPKHqFlksIr7GUJJXarb+Q4C
    mS5Qhk8ejBSZ/vR7lr58GF5Avz2zSgrQ== thi@thialfihar.org
    
(line breaks added for readability, it's one line)

And we can now put that line into some `authorized_keys` files on some machines for password-less 
authentication when we login remotely via SSH.

### Add a readable message

    > ./generate_fancy_ssh_key.py vanilla '++++thialfihar+org++++'
    new key pair:
    vanilla.new.pub
    vanilla.new
    
and the resulting file might look something like this:
    
    ssh-rsa AAAAB3NzaC1yc2EAAAAZAQAA++++thialfihar+org++++++AAAANwAAAIEAyWl/nX0ncnTG5yaxKk4qc
    GoyvKkMyqDTF7dDQByqnisovt8yxDsoQfm1QBDlHELZAz8+WmKpP8KxfobfprdYvNMLRgoInxryYM2ajXEYf6exd4
    PTlxc2jyh6hZZLCK+xlCSV2q2/kOApkuUIZPHowUmf70e5a+fBheQL89s0oK0= thi@thialfihar.org
    
All spaces will be replaced by '+'s and all other non-base64 chars will become '/'s.

`NOTE:` the source key pair must be unencrypted, as the script can't read private key files 
with a passphrase.

## How it works
### Read the public key
The public key file contains the encryption algorithm as first word: `ssh-rsa`, the last word 
is your name and the host the key belongs to: `thi@thialfihar.org`, and the middle is the 
interesting bit.

The middle is a [base64](http://en.wikipedia.org/wiki/Base64) representation of a binary data 
structure that looks something like this:

    4 bytes - unsigned int: length X of string to come
    X bytes - string: this will be 'ssh-rsa' (7 chars)

    4 bytes - unsigned int: length Y of byte array
    Y bytes - bigint of 'e'

    4 bytes - unsigned int: length Z of byte array
    Z bytes - bigint of 'n'

So this is easily parsed. See wikipedia RSA link above for details of what exactly `e` and `n` 
are for. For now we only need to know that both are relatively large numbers and together `(e, n)` 
forms our public key.

### Read the private key
We'll also need the private key, because it contains `p` and `q` such that `pq = n` and a key 
pair can only be generated if we know `p` and `q` (at least to our knowledge).

I cover some details on the private key and the SSH file structure for it in the script (see bottom), 
so I won't go into it much here. Just that it is contained in a 
[DER](http://en.wikipedia.org/wiki/Distinguished_Encoding_Rules) structure. 
(See also [ASN.1](http://en.wikipedia.org/wiki/ASN.1))

For reading and writing that DER structure I used a Python library called 
[pyasn1](http://pyasn1.sourceforge.net/), which worked very well.

### Generate new public key
Since `e` comes first and can actually be quite freely chosen, we just have to find some `e` that 
together with the other binary data will produce some readable message in the base64 encoded part 
of the public key.

We do that by first building the beginning of the binary data up to the 4 bytes for the length of 
the `e` chunk, which we'll assume to be 0 for now, as we only need the bytes there and don't care 
what the length will be later. Then we fill up that string with 0 bytes until the total length is 
a multiple of 6, because every chunk of 6 bytes is encoded to exactly 8 base64 bytes without any 
padding. Now we encode that string in base64 and in our special case of SSH RSA keys will always 
get this:

    AAAAB3NzaC1yc2EAAAAZAQAA
    
Now we take our message, which will be ''++++thialfihar+org++++'' in our case (keep in mind the 
limited base64 charset, so we have to replace spaces), and concatenate it to our base64 beginning:

    AAAAB3NzaC1yc2EAAAAKAQAA++++thialfihar+org++++

In order to make this a valid base64 string without padding again we need to get it to a length 
divisible by 8. We do this by adding more +s, and to get some separation from the rest of the key, 
let's add 8 '+'s even if the length is already a multiple of 8. In this case the length is 46, so we 
only need 2:

    AAAAB3NzaC1yc2EAAAAKAQAA++++thialfihar+org++++++

Now we have valid base64 encoded data, which we can decode, so we can read the binary data `e` must 
start with at the appropriate offset.

We also have to make sure our constructed `e` will work for our purpose, for which it must suffice 
`gcd(e, phi(n)) == 1`, where `phi` is
[Euler's totient function](http://en.wikipedia.org/wiki/Euler%27s_totient_function). 
We also should make sure `e` is a _good_ one. See RSA encryption for details on that, I'll ignore 
that for now, as I think it is incredibly improbable that the `e` we just generated is an insecure one.

Now `(e, n)` forms our new public key.

### Find matching private key
Of course we now need to build a new private key as well, so things will actually _work_. For this 
we just need to find a `d` such that `ed == 1 mod phi(n)`. This can easily be done with the 
[extended Euclidean algorithm](http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm). 
Afterwards `(d, n)` forms our new private key. We also adjust some exponents needed for the DER structure.

### Write new keys
Now we just pack everything back into an SSH-readable format. Generating the public and private key files.

