package set2

import "errors"

// PadBlockPKCS7 will pad any block to a specific block length blockSize (in bytes)
// we require blockSize >= len(block) and blockSize < 256
func PadBlockPKCS7(block []byte, blockSize byte) (paddedBlock []byte, err error) {
	if len(block) > int(blockSize) {
		return nil, errors.New("The block to pad is bigger than the target size")
	}
	paddedBlock = make([]byte, blockSize)
	copy(paddedBlock, block)
	padLength := int(blockSize) - len(block)
	if padLength == 0 {
		padding := make([]byte, blockSize)
		for i := 0; i < len(padding); i++ {
			padding[i] = blockSize
		}
		paddedBlock = append(paddedBlock, padding...)
	} else {
		for i := len(block); i < int(blockSize); i++ {
			paddedBlock[i] = byte(padLength)
		}
	}
	return paddedBlock, nil
}

// PadPCKS7 will pad an array of byte to a specific block length
func PadPCKS7(array []byte, blockSize byte) (paddedArray []byte) {
	size := int(blockSize)
	nbBlocks := len(array) / size
	lastBlock := array[nbBlocks*size:]
	paddedBlock, _ := PadBlockPKCS7(lastBlock, blockSize)
	paddedArray = make([]byte, len(array)-len(lastBlock)+len(paddedBlock))
	copy(paddedArray, array)
	for i := 0; i < len(paddedBlock); i++ {
		paddedArray[i+nbBlocks*size] = paddedBlock[i]
	}
	return paddedArray
}

// UnpadPKCS7 will remove the PKCS7 padding from an array
func UnpadPKCS7(array []byte) []byte {
	padding := int(array[len(array)-1])
	return array[:len(array)-padding]
}
