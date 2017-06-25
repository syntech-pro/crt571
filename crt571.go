package crt571

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	rs232 "github.com/dustin/go-rs232"
)

const (
	CRT571_SERVICE_TIMEOUT    = 5
	CRT571_SERVICE_QUEUE_SIZE = 10
	CRT571_BUFFER_MAX_LENGTH  = 1024
)

// Transpost constants
const (
	CRT571_STX byte = 0xf2
	CRT571_ETX byte = 0x03
	CRT571_CMT byte = 0x43
	CRT571_PMT byte = 0x50
	CRT571_EMT byte = 0x45
)

// Command (CM) constants
const (
	CRT571_CM_INITIALIZE                byte = 0x30 // Initialize CRT-571
	CRT571_CM_STATUS_REQUEST            byte = 0x31 // Inquire status
	CRT571_CM_CARD_MOVE                 byte = 0x32 // Card movement
	CRT571_CM_CARD_ENTRY                byte = 0x33 // From output gate
	CRT571_CM_CARD_TYPE                 byte = 0x50 // ICCard/RFCard TypeCheck
	CRT571_CM_CPUCARD_CONTROL           byte = 0x51 // CPU Card Applicatio Opertion
	CRT571_CM_SAM_CARD_CONTROL          byte = 0x52 // SAMCard Application Operation
	CRT571_CM_SLE4442_4428_CARD_CONTROL byte = 0x53 // SLE4442/4428CARD CONTROL
	CRT571_CM_IIC_MEMORYCARD            byte = 0x54 // 24C01—24C256Card Operation
	CRT571_CM_RFCARD_CONTROL            byte = 0x60 //Mifare standard card Type A & B T=CL protocol operation (13.56 MHZ)
	CRT571_CM_CARD_SERIAL_NUMBER        byte = 0xa2
	CRT571_CM_READ_CARD_CONFIG          byte = 0xa3
	CRT571_CM_READ_CRT571_VERSION       byte = 0xa4
	CRT571_CM_RECYCLEBIN_COUNTER        byte = 0xa5
)

// Card Status Code（st0,st1,st2)
const (
	CRT571_ST0_NO_CARD              = "0" //	No Card in CRT-571
	CRT571_ST0_ONE_CARD_IN_GATE     = "1" // One Card in gate
	CRT571_ST0_ONE_CARD_ON_POSITION = "2" // One Card on RF/IC Card Position

	CRT571_ST1_NO_CARD_IN_STACKER  = "0" //	No Card in stacker
	CRT571_ST1_FEW_CARD_IN_STACKER = "1" // Few Card in stacker
	CRT571_ST1_ENOUGH_CARDS_IN_BOX = "2" // Enough Cards in card box

	CRT571_ST2_ERROR_CARD_BIN_NOT_FULL = "0" // Error card bin not full
	CRT571_ST2_ERROR_CARD_BIN_FULL     = "1" // Error card bin full
)

// Parameters (PM) for command INITIALIZE (0x30)
const (
	CRT571_PM_INITIALIZE_MOVE_CARD              byte = 0x30 // If card is inside, move card to cardholding position
	CRT571_PM_INITIALIZE_MOVE_CARD_RETRACT      byte = 0x34 // If card is inside, move card to cardholding position and retract counter will work
	CRT571_PM_INITIALIZE_CAPTURE_CARD           byte = 0x31 // If card is inside, capture card error card bin
	CRT571_PM_INITIALIZE_CAPTURE_CARD_RETRACT   byte = 0x35 // If card is inside, capture card error card bin and retract counter will work
	CRT571_PM_INITIALIZE_DONT_MOVE_CARD         byte = 0x33 // If card is inside, does not move the card.
	CRT571_PM_INITIALIZE_DONT_MOVE_CARD_RETRACT byte = 0x37 // If card is inside, does not move the card and retract counter will work
)

type CRT571Service struct {
	config  CRT571Config
	chReq   chan CRT571Exchange
	port    *rs232.SerialPort
	address byte
}

type CRT571Config struct {
	BaudRate int
	Mode     string
	Path     string
	Address  int
}

type CRT571Exchange struct {
	Data         []byte
	ChanResponse chan []byte
	ChanError    chan error
	InProcess    bool
}

type CRT571Request struct {
	STX  byte    // Representing the start of text in a command or a response.
	ADDR byte    // Representing the address of CRT-571
	LEN  [2]byte // Length highlow byte
	CMT  byte    // Command head
	CM   byte    // Specify as command
	PM   byte    // Command parameter
	DATA []byte  // Transmission data
	ETX  byte    // End of text
	BCC  byte    // CRC Parity
}

type CRT571Response struct {
	STX  byte    // Representing the start of text in a command or a response.
	ADDR byte    // Representing the address of CRT-571
	LEN  [2]byte // Length highlow byte
	PMT  byte    // Return command head
	CM   byte    // Specify as command.
	PM   byte    // Command parameter
	ST0  byte    // Status code
	ST1  byte    // Status code
	ST2  byte    // Status code
	DATA []byte  // Transmission data
	ETX  byte    // End of text
	BCC  byte    // CRC Parity
}

type CRT571FailedResponse struct {
	STX  byte    // Representing the start of text in a command or a response
	ADDR byte    // Representing the address of CRT-571
	LEN  [2]byte // Length highlow byte
	EMT  byte    // Return command head
	CM   byte    // Specify as command.
	E1   byte    // Status code
	E0   byte    // Status code
	PM   byte    // Command parameter
	DATA []byte  // Transmission data
	ETX  byte    // End of text
	BCC  byte    // CRC Parity
}

var crt571errors = map[string]string{
	"00": "Reception of Undefined Command",
	"01": "Command Parameter Error",
	"02": "Command Sequence Error",
	"03": "Out of Hardware Support Command",
	"04": "Command Data Error",
	"05": "IC Card Contact Not Release",
	"10": "Card Jam",
	"12": "sensor error",
	"13": "Too Long-Card",
	"14": "Too Short-Card",
	"16": "Card move manually",
	"40": "Move card when recycling",
	"41": "Magnent of IC Card Error",
	"43": "Disable To Move Card To IC Card Position",
	"45": "Manually Move Card",
	"50": "Received Card Counter Overflow",
	"51": "Motor error",
	"60": "Short Circuit of IC Card Supply Power",
	"61": "Activiation of Card False",
	"62": "Command Out Of IC Card Support",
	"65": "Disablity of IC Card",
	"66": "Command Out Of IC Current Card Support",
	"67": "IC Card Transmittion Error",
	"68": "IC Card Transmittion Overtime",
	"69": "CPU/SAM Non-Compliance To EMV Standard",
	"A0": "Empty-Stacker",
	"A1": "Full-Stacker",
	"B0": "Not Reset",
}

var modes = map[string]rs232.SerConf{
	"8N1": rs232.S_8N1,
	"7E1": rs232.S_7E1,
	"7O1": rs232.S_7O1,
}

// Init CRT571
func InitCRT571Service(config CRT571Config) (service CRT571Service, err error) {

	service = CRT571Service{config: config}

	// Init reader goroutine and channels
	service.chReq = make(chan CRT571Exchange, CRT571_SERVICE_QUEUE_SIZE)

	service.port, err = rs232.OpenPort(config.Path, config.BaudRate, parseMode(config.Mode))
	if err != nil {
		log.Fatalf("Error opening port %q: %s", config.Path, err)
	}

	service.address = byte(config.Address)

	return
}

// Exchange with CRT-571
func (service *CRT571Service) Exchange(data []byte) ([]byte, error) {
	buf := make([]byte, CRT571_BUFFER_MAX_LENGTH)

	// write to CRT-571
	len, err := service.port.Write(data)
	if err != nil {
		return nil, err
	}
	// TODO check size of write data

	// read from CRT-571
	len, err = service.port.Read(buf)
	if err != nil {
		return nil, err
	}
	if len < 1 {
		return nil, errors.New("Read buffer is empty")
	}
	// TODO check size of read data

	return buf, nil

}

// Make request to CRT571
func (service *CRT571Service) MakeRequest(cm, pm byte, data []byte) ([]byte, error) {

	var b bytes.Buffer

	// make data length bytes
	datalen := make([]byte, 2)
	binary.BigEndian.PutUint16(datalen, uint16(len(data)))

	b.WriteByte(CRT571_STX)      // STX
	b.WriteByte(service.address) // ADDR
	b.Write(datalen)             // LEN
	b.WriteByte(CRT571_CMT)      // CMT
	b.WriteByte(cm)              // CM
	b.WriteByte(pm)              // PM
	b.Write(data)                // DATA
	b.WriteByte(CRT571_ETX)      // ETX
	b.WriteByte(CRT571_STX)      // STX

	// BCC
	bcc := bccCalculate(b)
	b.WriteByte(bcc)

	if b.Len() > CRT571_BUFFER_MAX_LENGTH {
		return nil, errors.New("Exceed max packet size for CRT-571")
	}

	buf, err := service.Exchange(b.Bytes())
	if err != nil {
		return nil, err
	}

	switch buf[4] {
	case CRT571_PMT: // Positve response
		return buf[:], nil

	case CRT571_EMT: // Failed response
		return nil, errors.New("Failed response") // TODO add error code
	}

	return nil, nil
}

// Initialize CRT571 device
func (service *CRT571Service) Initialization(pm byte) error {
	service.MakeRequest(CRT571_CM_INITIALIZE, pm, nil)
	return nil
}

func bccCalculate(data bytes.Buffer) byte {
	return 0x99
}

func parseMode(s string) rs232.SerConf {
	rv, ok := modes[s]
	if !ok {
		log.Fatalf("Invalid mode: %v", s)
	}
	return rv
}
