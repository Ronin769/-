# coding:UTF-8

import sys
import os

# IMPORTANT: The block size MUST be less than or equal to the key size!
# (Note: The block size is in bytes, the key size is in bits. There
# are 8 bits in 1 byte.)
DEFAULT_BLOCK_SIZE = 128 # 128 bytes
BYTE_SIZE = 256 # One byte has 256 different values.
#KeySize = 0

def encript(message,pubkeyfilename5):
    # Runs a test that encrypts a message to a file or decrypts a message
    # from a file.
    #message = '''"Journalists belong in the gutter because that is where the ruling classes throw their guilty secrets." -Gerald Priestland "The Founding Fathers gave the free press the protection it must have to bare the secrets of government and inform the people." -Hugo Black'''

    #filename = 'encrypted_file.exc' # the file to write to/read from
    mode = 'encrypt' # set to 'encrypt' or 'decrypt'
    pubKeyFilename = pubkeyfilename5
    #print('正在加密数据并写入到文件 %s...' % (filename))
    encryptedText = encryptAndWriteToFile(pubKeyFilename, message)
    #print('文件加密成功！')

    return encryptedText


def decript(message,pubkeyfilename6):
    # Runs a test that encrypts a message to a file or decrypts a message
    # from a file.
    #filename = 'encrypted_file.exc' # the file to write to/read from
    privKeyFilename = pubkeyfilename6
    #print('从文件 %s 读取并加密...' % (filename))
    decryptedText = readFromFileAndDecrypt(message,privKeyFilename)
    #print('文件解密成功')
    
    return decryptedText

def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a string message to a list of block integers. Each integer
    # represents 128 (or whatever blockSize is set to) string characters.

    messageBytes = message.encode('ascii') # convert the string to bytes

    blockInts = []
    for blockStart in range(0, len(messageBytes), blockSize):
        # Calculate the block integer for this block of text
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a list of block integers to the original message string.
    # The original message length is needed to properly convert the last
    # block integer.
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer.
                asciiNumber = blockInt // (BYTE_SIZE ** i)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts the message string into a list of block integers, and then
    # encrypts each block integer. Pass the PUBLIC key to encrypt.
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):
        # ciphertext = plaintext ^ e mod n
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Decrypts a list of encrypted block ints into the original message
    # string. The original message length is required to properly decrypt
    # the last block. Be sure to pass the PRIVATE key to decrypt.
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        # plaintext = ciphertext ^ d mod n
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)

	
def readKeyFile(keyFilename):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    if os.path.exists(keyFilename) == True:
        fo = open(keyFilename)
        content = fo.read()
        fo.close()
        keySize, n, EorD = content.split(',')
        return (int(keySize), int(n), int(EorD))
    #else:
        #print('您要读取的密钥文件不存在！')
        #sys.exit('您要读取的密钥文件不存在！')


def encryptAndWriteToFile(keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):
    # Using a key from a key file, encrypt the message and save it to a
    # file. Returns the encrypted message string.
    keySize, n, e = readKeyFile(keyFilename)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8: # * 8 to convert bytes to bits
        sys.exit('错误: 块大小是 %s 位，密钥大小是 %s 位。RSA密码要求块大小等于或大于密钥的大小。 要么减少块大小，要么使用不同的密钥。' % (blockSize * 8, keySize))


    # Encrypt the message
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)

    # Convert the large int values to one string value.
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)

    # Write out the encrypted string to the output file.
    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)
    #fo = open(messageFilename, 'w')
    #fo.write(encryptedContent)
    #fo.close()
    # Also return the encrypted string.
    return encryptedContent


def readFromFileAndDecrypt(message,keyFilename):
    # Using a key from a key file, read an encrypted message from a file
    # and then decrypt it. Returns the decrypted message string.
    keySize, n, d = readKeyFile(keyFilename)


    # Read in the message length and the encrypted message from the file.
    messageLength, blockSize, encryptedMessage = message.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8: # * 8 to convert bytes to bits
        sys.exit('错误: 块大小是 %s 位， 密钥大小是 %s 位。 RSA密码要求块大小等于或大于密钥的大小。 您是否指定了正确的密钥文件和加密文件?' % (blockSize * 8, keySize))

    # Convert the encrypted message into large int values.
    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    # Decrypt the large int values.
    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)
    #else:
    #print('要解密的文件 %s 不存在！' % (messageFilename))
    #sys.exit('要解密的文件 %s 不存在！' % (messageFilename))

# If rsaCipher.py is run (instead of imported as a module) call
# the main() function.
if __name__ == '__main__':
    main()
