package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	maxInputBuffer = 1024
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
)

const (
	TPM_MLKEM_512_ENABLED uint32 = 1 << iota
	TPM_MLKEM_768_ENABLED
	TPM_MLKEM_1024_ENABLED
	TPM_MLDSA_44_ENABLED
	TPM_MLDSA_65_ENABLED
	TPM_MLDSA_87_ENABLED
	TPM_MLDSA_ALLOW_EXTERNAL_MU
)

type TPMA_ML_PARAMETER_SET struct {
	ID        uint32
	BitFields uint32 // Acts as storage for multiple bit booleans
}

func (u *TPMA_ML_PARAMETER_SET) HasFlag(flag uint32) bool {
	return (u.BitFields & flag) != 0
}

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	log.Println("======= Init  ========")

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	// first try to read what the max MLDSA buffer and set it as maxInputBuffer variable
	// 11.3.4 MAX_MLDSA_SIG_SIZE  pg 186 https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf
	getCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTInputBuffer),
		PropertyCount: 1,
	}
	getRsp, err := getCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("can't get capabilities %v", err)
	}

	tp, err := getRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		log.Fatalf("can't read capabilities%v", err)
	}

	blockSize := int(tp.TPMProperty[0].Value)
	log.Printf("TPM Max buffer %d", blockSize)

	// 8.13 TPMA_ML_PARAMETER_SET
	// This Table 47 attribute is used to report the supported ML-KEM and ML-DSA parameter sets, as well as
	// support for allowExternalMu. This structure may be read using TPM2_GetCapability(capability ==
	// TPM_CAP_TPM_PROPERTIES, property == TPM_PT_ML_PARAMETER_SETS).
	// Table 47: Definition of (UINT32) TPMA_ML_PARAMETER_SET Bits
	// Bit Name Definition
	// 0 mlKem_512 Indicates support for TPM_MLKEM_512
	// 1 mlKem_768 Indicates support for TPM_MLKEM_768
	// 2 mlKem_1024 Indicates support for TPM_MLKEM_1024
	// 3 mlDsa_44 Indicates support for TPM_MLDSA_44
	// 4 mlDsa_65 Indicates support for TPM_MLDSA_65
	// 5 mlDsa_87 Indicates support for TPM_MLDSA_87
	// 6 extMu Indicates support for allowExternalMu for ML-DSA

	//Bits:          111111
	//Padded Bits:   00000000000000000000000000111111

	getCmdParam := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMLParameterSet),
		PropertyCount: 1,
	}
	getRspParam, err := getCmdParam.Execute(rwr)
	if err != nil {
		log.Fatalf("can't get capabilities %v", err)
	}

	tparam, err := getRspParam.CapabilityData.Data.TPMProperties()
	if err != nil {
		log.Fatalf("can't read capabilities%v", err)
	}

	bitStr := strconv.FormatUint(uint64(tparam.TPMProperty[0].Value), 2)

	// Format with leading zeros to show all 32 bits
	paddedStr := fmt.Sprintf("%032b", tparam.TPMProperty[0].Value)
	log.Println("TPMPTMLParameterSet Bits:         ", bitStr)    // Bits:
	log.Println("TPMPTMLParameterSet Padded Bits:  ", paddedStr) // Output:

	f := TPMA_ML_PARAMETER_SET{BitFields: tparam.TPMProperty[0].Value}

	log.Printf("TPM_MLKEM_512_ENABLED %t\n", f.HasFlag(TPM_MLKEM_512_ENABLED))
	log.Printf("TPM_MLKEM_768_ENABLED %t\n", f.HasFlag(TPM_MLKEM_768_ENABLED))
	log.Printf("TPM_MLKEM_1024_ENABLED %t\n", f.HasFlag(TPM_MLKEM_1024_ENABLED))
	log.Printf("TPM_MLDSA_44_ENABLED %t\n", f.HasFlag(TPM_MLDSA_44_ENABLED))
	log.Printf("TPM_MLDSA_65_ENABLED %t\n", f.HasFlag(TPM_MLDSA_65_ENABLED))
	log.Printf("TPM_MLDSA_87_ENABLED %t\n", f.HasFlag(TPM_MLDSA_87_ENABLED))

	log.Printf("TPM_MLDSA_ALLOW_EXTERNAL_MU %t\n", f.HasFlag(TPM_MLDSA_ALLOW_EXTERNAL_MU))
}
