package crt571

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	rs232 "github.com/syntech-pro/go-rs232"
	//rs232 "../go-rs232"
)

const (
	CRT571_BUFFER_MAX_LENGTH = 1024
)

// Transpost constants
const (
	CRT571_STX byte = 0xf2
	CRT571_ETX byte = 0x03
	CRT571_CMT byte = 0x43
	CRT571_PMT byte = 0x50
	CRT571_EMT byte = 0x45
	CRT571_ACK byte = 0x06 // Acknowledge
	CRT571_NAK byte = 0x15 // Negative acknow
	CRT571_EOT byte = 0x04 // Clear the line
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
	CRT571_ST0_NO_CARD              = 0x30 // No Card in CRT-571
	CRT571_ST0_ONE_CARD_IN_GATE     = 0x31 // One Card in gate
	CRT571_ST0_ONE_CARD_ON_POSITION = 0x32 // One Card on RF/IC Card Position

	CRT571_ST1_NO_CARD_IN_STACKER  = 0x30 // No Card in stacker
	CRT571_ST1_FEW_CARD_IN_STACKER = 0x31 // Few Card in stacker
	CRT571_ST1_ENOUGH_CARDS_IN_BOX = 0x32 // Enough Cards in card box

	CRT571_ST2_ERROR_CARD_BIN_NOT_FULL = 0x30 // Error card bin not full
	CRT571_ST2_ERROR_CARD_BIN_FULL     = 0x31 // Error card bin full
)

// Parameters (PM) for command INITIALIZE (PM=0x30)
const (
	CRT571_PM_INITIALIZE_MOVE_CARD              byte = 0x30 // If card is inside, move card to cardholding position
	CRT571_PM_INITIALIZE_MOVE_CARD_RETRACT      byte = 0x34 // If card is inside, move card to cardholding position and retract counter will work
	CRT571_PM_INITIALIZE_CAPTURE_CARD           byte = 0x31 // If card is inside, capture card error card bin
	CRT571_PM_INITIALIZE_CAPTURE_CARD_RETRACT   byte = 0x35 // If card is inside, capture card error card bin and retract counter will work
	CRT571_PM_INITIALIZE_DONT_MOVE_CARD         byte = 0x33 // If card is inside, does not move the card.
	CRT571_PM_INITIALIZE_DONT_MOVE_CARD_RETRACT byte = 0x37 // If card is inside, does not move the card and retract counter will work
)

// Parameters (PM) for command Status Request (PM=0x31)
const (
	CRT571_PM_STATUS_DEVICE byte = 0x30 // Report CRT-571 status
	CRT571_PM_STATUS_SENSOR byte = 0x31 // Report sensor status
)

type CRT571Service struct {
	config  CRT571Config
	chReq   chan CRT571Exchange
	port    *rs232.SerialPort
	address byte
}

type CRT571Config struct {
	BaudRate    int
	Path        string
	Address     int
	ReadTimeout int // Read timeout in Millisecond
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

var crt571_ST0_state = map[byte]string{
	CRT571_ST0_NO_CARD:              "No Card in CRT-571",
	CRT571_ST0_ONE_CARD_IN_GATE:     "One Card in gate",
	CRT571_ST0_ONE_CARD_ON_POSITION: "One Card on RF/IC Card Position",
}

var crt571_ST1_state = map[byte]string{
	CRT571_ST1_NO_CARD_IN_STACKER:  "No Card in stacker",
	CRT571_ST1_FEW_CARD_IN_STACKER: "Few Card in stacker",
	CRT571_ST1_ENOUGH_CARDS_IN_BOX: "Enough Cards in card box",
}

var crt571_ST2_state = map[byte]string{
	CRT571_ST2_ERROR_CARD_BIN_NOT_FULL: "Error card bin not full",
	CRT571_ST2_ERROR_CARD_BIN_FULL:     "Error card bin full",
}

var crt571_errors = map[string]string{
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

// Init CRT571
func InitCRT571Service(config CRT571Config) (service CRT571Service, err error) {

	service = CRT571Service{config: config}

	// Init reader goroutine and channels
	//service.chReq = make(chan CRT571Exchange, CRT571_SERVICE_QUEUE_SIZE)

	service.port, err = rs232.OpenPort(config.Path, config.BaudRate, rs232.S_8N1X)
	if err != nil {
		log.Fatalf("[ERROR] Error opening port %q: %s", config.Path, err)
	}

	service.address = byte(config.Address)
	//service.port.SetNonblock()
	service.port.SetInputAttr(0, time.Duration(config.ReadTimeout)*time.Millisecond)

	return
}

func (service *CRT571Service) read(buf []byte) (int, error) {
	i := 0
	for {
		len, err := service.port.Read(buf[i:])
		if err != nil {
			if err == io.EOF {
				log.Printf("[INFO] read(): Read EOF data:[% x] len:%v", buf[i:i+len], len)
				break
			}
			log.Printf("[ERROR] read(): Read error:%s", err)
			return 0, err
		}
		//		log.Printf("[INFO] read(): Read data:[% x] len:%v", buf[i:i+len], len)
		log.Printf("[INFO] read(): Read buffer:[% x] len:%v", buf[i:i+len], len)
		i += len
	}
	return i, nil
}

// Exchange with CRT-571
func (service *CRT571Service) exchange(data []byte) ([]byte, error) {
	buf := make([]byte, CRT571_BUFFER_MAX_LENGTH)

	log.Printf("[INFO] exchange(): Write data:[% x] len: %v", data, len(data))

	// write to device
	len, err := service.port.Write(data)
	if err != nil {
		log.Printf("[ERROR] exchange(): Write error:%s", err)
		return nil, err
	}
	log.Printf("[INFO] exchange(): Wrote len: %v", len)
	// TODO check size of write data

	// read ACK response
	len, err = service.read(buf)
	if err != nil {
		log.Printf("[ERROR] exchange(): Read ACK  error:%s", err)
		return nil, err
	}
	log.Printf("[INFO] exchange(): Read ACK data:[% x]", buf[:len])
	if buf[0] != CRT571_ACK {
		log.Print("[ERROR] exchange(): ACK is absent")
		return nil, errors.New("ACK is absent")
		// TODO send NAK
	}

	// read command response
	if len > 1 {
		buf = buf[1:]
		len -= 1
	} else {
		len, err = service.read(buf)
		if err != nil {
			log.Printf("[ERROR] exchange(): Read response error:%s", err)
			return nil, err
		}
	}
	log.Printf("[INFO] exchange(): Read response data:[% x] len:%v", buf[:len], len)

	// check bcc
	if !bccCheck(buf[len-1], buf[:len-1]) {
		log.Print("[ERROR] exchange(): BCC response check fail!")
		//return nil, errors.New("BCC response check fail!")
	} else {
		log.Print("[INFO] exchange(): BCC response check success")
	}

	// write ACK to device
	len, err = service.port.Write([]byte{CRT571_ACK})
	if err != nil {
		log.Printf("[ERROR] exchange(): Write ACK error:%s", err)
		return nil, err
	}
	log.Printf("[INFO] exchange(): Wrote ACK len: %v", len)

	return buf, nil

}

// Make request to CRT571
func (service *CRT571Service) request(cm, pm byte, data []byte) ([]byte, []byte, error) {

	log.Printf("[INFO] request(): Call with CM:%x, PM:%x, Data:[%x]", cm, pm, data)

	var b bytes.Buffer

	// make data length bytes
	datalenb := make([]byte, 2)
	binary.BigEndian.PutUint16(datalenb, uint16(len(data)+3))

	b.WriteByte(CRT571_STX)      // STX
	b.WriteByte(service.address) // ADDR
	b.Write(datalenb)            // LENM;12MM;18M[]
	b.WriteByte(CRT571_CMT)      // CMT
	b.WriteByte(cm)              // CM
	b.WriteByte(pm)              // PM
	b.Write(data)                // DATA
	b.WriteByte(CRT571_ETX)      // ETX

	// BCC
	bcc := bccCalc(b.Bytes())
	b.WriteByte(bcc)

	log.Printf("[INFO] request(): buffer:[% x]", b.Bytes())

	if b.Len() > CRT571_BUFFER_MAX_LENGTH {
		return nil, nil, errors.New("[ERROR] Exceed max packet size for CRT-571")
	}

	buf, err := service.exchange(b.Bytes())
	if err != nil {
		return nil, nil, err
	}

	datalen := int(binary.BigEndian.Uint16(buf[2:4]))
	switch buf[4] {
	case CRT571_PMT: // Positve response
		log.Printf("[INFO] request(): Get positive response. State:[% x]=[%s;%s;%s] data:[% x]=[%[5]s]", buf[7:10], crt571_ST0_state[buf[7]], crt571_ST1_state[buf[8]], crt571_ST2_state[buf[9]], buf[10:10+datalen-6])
		return buf[7:10], buf[10 : 10+datalen], nil

	case CRT571_EMT: // Failed response
		log.Printf("[ERROR] request(): Get negative response. State: [% x] data:[% x]=[%[2]s]", buf[6:8], buf[9:9+datalen-5])
		return nil, buf[9 : 9+datalen], errors.New(crt571_errors[string(buf[6:8])])
	}

	return nil, nil, errors.New(fmt.Sprintf("[ERROR] Unknow data response status [% x]", buf[4]))
}

// Initialize CRT571 device
func (service *CRT571Service) Initialization(pm byte) error {
	log.Printf("[INFO] Initialization(): PM:[%x]", pm)

	service.request(CRT571_CM_INITIALIZE, pm, nil)
	return nil
}

// Initialize CRT571 device
func (service *CRT571Service) StatusRequest(pm byte) error {
	log.Printf("[INFO] StatusRequest(): PM:[%x]", pm)

	service.request(CRT571_CM_STATUS_REQUEST, pm, nil)
	return nil
}

func bccCalc(a []byte) byte {
	bcc := byte(0)
	n := len(a)

	for i := 0; i < n; i++ {
		bcc = bcc ^ a[i]
	}
	return bcc
}

func bccCheck(bcc byte, data []byte) bool {
	bcc2 := bccCalc(data)
	log.Printf("[INFO] bccCalculate(): data:[% x] bcc:[%x] bcc calculated:[%x]", data, bcc, bcc2)

	if bcc == bcc2 {
		return true
	}
	return false
}
