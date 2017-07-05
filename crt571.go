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

	// Transpost constants
	CRT571_STX  byte = 0xf2
	CRT571_ETX  byte = 0x03
	CRT571_CMT  byte = 0x43
	CRT571_PMT  byte = 0x50
	CRT571_EMT  byte = 0x45
	CRT571_EMT2 byte = 0x4E
	CRT571_ACK  byte = 0x06 // Acknowledge
	CRT571_NAK  byte = 0x15 // Negative acknow
	CRT571_EOT  byte = 0x04 // Clear the line

	// Command (CM) constants
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

	// Card Status Code（st0,st1,st2)
	CRT571_ST0_NO_CARD              byte = 0x30 // No Card in CRT-571
	CRT571_ST0_ONE_CARD_IN_GATE     byte = 0x31 // One Card in gate
	CRT571_ST0_ONE_CARD_ON_POSITION byte = 0x32 // One Card on RF/IC Card Position

	CRT571_ST1_NO_CARD_IN_STACKER  byte = 0x30 // No Card in stacker
	CRT571_ST1_FEW_CARD_IN_STACKER byte = 0x31 // Few Card in stacker
	CRT571_ST1_ENOUGH_CARDS_IN_BOX byte = 0x32 // Enough Cards in card box

	CRT571_ST2_ERROR_CARD_BIN_NOT_FULL byte = 0x30 // Error card bin not full
	CRT571_ST2_ERROR_CARD_BIN_FULL     byte = 0x31 // Error card bin full

	// Parameters for command INITIALIZE (PM=0x30)
	CRT571_PM_INITIALIZE_MOVE_CARD              byte = 0x30 // If card is inside, move card to cardholding position
	CRT571_PM_INITIALIZE_MOVE_CARD_RETRACT      byte = 0x34 // If card is inside, move card to cardholding position and retract counter will work
	CRT571_PM_INITIALIZE_CAPTURE_CARD           byte = 0x31 // If card is inside, capture card error card bin
	CRT571_PM_INITIALIZE_CAPTURE_CARD_RETRACT   byte = 0x35 // If card is inside, capture card error card bin and retract counter will work
	CRT571_PM_INITIALIZE_DONT_MOVE_CARD         byte = 0x33 // If card is inside, does not move the card.
	CRT571_PM_INITIALIZE_DONT_MOVE_CARD_RETRACT byte = 0x37 // If card is inside, does not move the card and retract counter will work

	// Parameters for command Status Request (PM=0x31)
	CRT571_PM_STATUS_DEVICE byte = 0x30 // Report CRT-571 status
	CRT571_PM_STATUS_SENSOR byte = 0x31 // Report sensor status

	// Parameters for command Card Move  Request (PM=0x32)
	CRT571_PM_CARD_MOVE_HOLD      byte = 0x30 // Move card to card holding positon
	CRT571_PM_CARD_MOVE_IC_POS    byte = 0x31 // Move card to IC card position
	CRT571_PM_CARD_MOVE_RF_POS    byte = 0x32 // Move card to RF card position
	CRT571_PM_CARD_MOVE_ERROR_BIN byte = 0x33 // Move card to error card bin
	CRT571_PM_CARD_MOVE_GATE      byte = 0x39 // Move card to gate

	// Parameters for command Card Entry From output gate (PM=0x33)
	CRT571_PM_CARD_ENTRY_ENABLE  byte = 0x30 // Enable card entry from output gate
	CRT571_PM_CARD_ENTRY_DISABLE byte = 0x31 // Disable card entry from ouput gate

	// Parameters for command Card Type
	CRT571_PM_CARD_TYPE_IC byte = 0x30 // Autocheck ICCardType
	CRT571_PM_CARD_TYPE_RF byte = 0x31 // Autocheck RFCardType

	// Parameters for command CPU Card Application Opertion
	CRT571_PM_CPUCARD_CONTROL_COLD_RESET   byte = 0x30 // CPUCard cold reset
	CRT571_PM_CPUCARD_CONTROL_POWER_DOWN   byte = 0x31 // CPUCard power down
	CRT571_PM_CPUCARD_CONTROL_STATUS_CHECK byte = 0x32 // CPUCard status check
	CRT571_PM_CPUCARD_CONTROL_TO_APDU      byte = 0x33 // T=0  CPUCard APDU data exchange
	CRT571_PM_CPUCARD_CONTROL_T1_APDU      byte = 0x34 // T=1  CPUCard APDU data exchange
	CRT571_PM_CPUCARD_CONTROL_HOT_RESET    byte = 0x38 // CPUCard hot reset
	CRT571_PM_CPUCARD_CONTROL_AUTO_APDU    byte = 0x39 // Auto distinguish T=0/T=1 CPUCard APDU data exchange

	// Parameters for command SAMCard Application Operation
	CRT571_PM_SAMCARD_CONTROL_COLD_RESET   byte = 0x30 // SAMCard cold reset
	CRT571_PM_SAMCARD_CONTROL_POWER_DOWN   byte = 0x31 // SAMCard power down
	CRT571_PM_SAMCARD_CONTROL_STATUS_CHECK byte = 0x32 // SAMCard status check
	CRT571_PM_SAMCARD_CONTROL_TO_APDU      byte = 0x33 // T=0  SAMCard APDU data exchange
	CRT571_PM_SAMCARD_CONTROL_T1_APDU      byte = 0x34 // T=1  SAMCard APDU data exchange
	CRT571_PM_SAMCARD_CONTROL_HOT_RESET    byte = 0x38 // SAMCard hot reset
	CRT571_PM_SAMCARD_CONTROL_AUTO_APDU    byte = 0x39 // Auto distinguish T=0/T=1 CPUCard APDU data exchange
	CRT571_PM_SAMCARD_CONTROL_STAND        byte = 0x40 // Choose SAMCard stand

	// Parameters for command SLE4442/4428CARD CONTROL
	CRT571_PM_SLE4442_4428_CARD_CONTROL_RESET                byte = 0x30 // SLE4442/4428Card reset
	CRT571_PM_SLE4442_4428_CARD_CONTROL_POWER_DOWN           byte = 0x31 // SLE4442/4428Card power down
	CRT571_PM_SLE4442_4428_CARD_CONTROL_CARD_STATUS          byte = 0x32 // Browse SLE4442/4428Card status
	CRT571_PM_SLE4442_4428_CARD_CONTROL_SLE4442_CARD_OPERATE byte = 0x33 // Operate SLE4442Card
	CRT571_PM_SLE4442_4428_CARD_CONTROL_SLE4428_CARD_OPERATE byte = 0x34 // Operate SLE4428Card

	// Parameters for command 24C01—24C256Card Operation
	CRT571_PM_IIC_MEMORYCARD_RESET      byte = 0x30 // IICCard reset
	CRT571_PM_IIC_MEMORYCARD_POWER_DOWN byte = 0x31 // IICCard down power
	CRT571_PM_IIC_MEMORYCARD_STATUS     byte = 0x32 // ICheck IICCard status
	CRT571_PM_IIC_MEMORYCARD_READ       byte = 0x33 // Read IICCard
	CRT571_PM_IIC_MEMORYCARD_WRITE      byte = 0x34 // Write IICCard

	// Parameters for command Mifare standard card Type A & BT=CL protocol operation
	CRT571_PM_RFCARD_CONTROL_STARTUP        byte = 0x30 // RF Card startup
	CRT571_PM_RFCARD_CONTROL_POWER_DOWN     byte = 0x31 // RF Card down power
	CRT571_PM_RFCARD_CONTROL_STATUS         byte = 0x32 // RF Card operation status check
	CRT571_PM_RFCARD_CONTROL_CARD_RW        byte = 0x33 // Mifare standard Card read/write
	CRT571_PM_RFCARD_CONTROL_TYPEA_APDU     byte = 0x34 // Type A standard T=CLCard APDU data exchange
	CRT571_PM_RFCARD_CONTROL_TYPEB_APDU     byte = 0x35 // Type B standard T=CLCard APDU data exchange
	CRT571_PM_RFCARD_CONTROL_ENABLE_DISABLE byte = 0x39 // RF Card enable/disable

	// Parameters for command Read Card Serial number
	CRT571_PM_CARD_SERIAL_NUMBER_READ byte = 0x30 // Read Card Serial number

	// Parameters for command Read Card configuration information
	CRT571_PM_READ_CARD_CONFIG byte = 0x30 // Read Card configuration information

	// Parameters for command Read Card software version information
	CRT571_PM_READ_CRT571_VERSION byte = 0x30 // Read Card software version information

	// Parameters for command RECYCLEBIN COUNTER
	CRT571_PM_RECYCLEBIN_COUNTER_READ     byte = 0x30 // Read number of counter of Card error card bin
	CRT571_PM_RECYCLEBIN_COUNTER_INITIATE byte = 0x31 // Initiate card error card bin counter
)

var CRT571Commands = map[byte]string{
	CRT571_CM_INITIALIZE:                "Initialize CRT-571",
	CRT571_CM_STATUS_REQUEST:            "Inquire status",
	CRT571_CM_CARD_MOVE:                 "Card movement",
	CRT571_CM_CARD_ENTRY:                "From output gate",
	CRT571_CM_CARD_TYPE:                 "ICCard/RFCard TypeCheck",
	CRT571_CM_CPUCARD_CONTROL:           "CPU Card Applicatio Opertion",
	CRT571_CM_SAM_CARD_CONTROL:          "SAMCard Application Operation",
	CRT571_CM_SLE4442_4428_CARD_CONTROL: "SLE4442/4428CARD CONTROL",
	CRT571_CM_IIC_MEMORYCARD:            "24C01—24C256Card Operation",
	CRT571_CM_RFCARD_CONTROL:            "Mifare standard card Type A & B T=CL protocol operation (13.56 MHZ)",
	CRT571_CM_CARD_SERIAL_NUMBER:        "Read Card Serial number",
	CRT571_CM_READ_CARD_CONFIG:          "Read Card configuration information",
	CRT571_CM_READ_CRT571_VERSION:       "Read Card software version information",
	CRT571_CM_RECYCLEBIN_COUNTER:        "Recycle bin counter",
}

var CRT571CardStatus = map[string]map[byte]string{
	"ST0": {
		CRT571_ST0_NO_CARD:              "No Card in CRT-571",
		CRT571_ST0_ONE_CARD_IN_GATE:     "One Card in gate",
		CRT571_ST0_ONE_CARD_ON_POSITION: "One Card on RF/IC Card Position",
	},
	"ST1": {
		CRT571_ST1_NO_CARD_IN_STACKER:  "No Card in stacker",
		CRT571_ST1_FEW_CARD_IN_STACKER: "Few Card in stacker",
		CRT571_ST1_ENOUGH_CARDS_IN_BOX: "Enough Cards in card box",
	},
	"ST2": {
		CRT571_ST2_ERROR_CARD_BIN_NOT_FULL: "Error card bin not full",
		CRT571_ST2_ERROR_CARD_BIN_FULL:     "Error card bin full",
	},
}

var CRT571PMInfo = map[byte]map[byte]string{
	CRT571_CM_INITIALIZE: {
		CRT571_PM_INITIALIZE_MOVE_CARD:              "If card is inside, move card to cardholding position",
		CRT571_PM_INITIALIZE_MOVE_CARD_RETRACT:      "If card is inside, move card to cardholding position and retract counter will work",
		CRT571_PM_INITIALIZE_CAPTURE_CARD:           "If card is inside, capture card error card bin",
		CRT571_PM_INITIALIZE_CAPTURE_CARD_RETRACT:   "If card is inside, capture card error card bin and retract counter will work",
		CRT571_PM_INITIALIZE_DONT_MOVE_CARD:         "If card is inside, does not move the card",
		CRT571_PM_INITIALIZE_DONT_MOVE_CARD_RETRACT: "If card is inside, does not move the card and retract counter will work",
	},
	CRT571_CM_STATUS_REQUEST: {
		CRT571_PM_STATUS_DEVICE: "Report CRT-571 status",
		CRT571_PM_STATUS_SENSOR: "Report sensor status",
	},
	CRT571_CM_CARD_MOVE: {
		CRT571_PM_CARD_MOVE_HOLD:      "Move card to card holding positon",
		CRT571_PM_CARD_MOVE_IC_POS:    "Move card to IC card position",
		CRT571_PM_CARD_MOVE_RF_POS:    "Move card to RF card position",
		CRT571_PM_CARD_MOVE_ERROR_BIN: "Move card to error card bin",
		CRT571_PM_CARD_MOVE_GATE:      "Move card to gate",
	},
	CRT571_CM_CARD_ENTRY: {
		CRT571_PM_CARD_ENTRY_ENABLE:  "Enable card entry from output gate",
		CRT571_PM_CARD_ENTRY_DISABLE: "Disable card entry from ouput gate",
	},
	CRT571_CM_CARD_TYPE: {
		CRT571_PM_CARD_TYPE_IC: "Autocheck ICCardType",
		CRT571_PM_CARD_TYPE_RF: "Autocheck RFCardType",
	},
	CRT571_CM_CPUCARD_CONTROL: {
		CRT571_PM_CPUCARD_CONTROL_COLD_RESET:   "CPUCard cold reset",
		CRT571_PM_CPUCARD_CONTROL_POWER_DOWN:   "CPUCard power down",
		CRT571_PM_CPUCARD_CONTROL_STATUS_CHECK: "CPUCard status check",
		CRT571_PM_CPUCARD_CONTROL_TO_APDU:      "T=0  CPUCard APDU data exchange",
		CRT571_PM_CPUCARD_CONTROL_T1_APDU:      "T=1  CPUCard APDU data exchange",
		CRT571_PM_CPUCARD_CONTROL_HOT_RESET:    "CPUCard hot reset",
		CRT571_PM_CPUCARD_CONTROL_AUTO_APDU:    "Auto distinguish T=0/T=1 CPUCard APDU data exchange",
	},
	CRT571_CM_SAM_CARD_CONTROL: {
		CRT571_PM_SAMCARD_CONTROL_COLD_RESET:   "SAMCard cold reset",
		CRT571_PM_SAMCARD_CONTROL_POWER_DOWN:   "SAMCard power down",
		CRT571_PM_SAMCARD_CONTROL_STATUS_CHECK: "SAMCard status check",
		CRT571_PM_SAMCARD_CONTROL_TO_APDU:      "T=0  SAMCard APDU data exchange",
		CRT571_PM_SAMCARD_CONTROL_T1_APDU:      "T=1  SAMCard APDU data exchange",
		CRT571_PM_SAMCARD_CONTROL_HOT_RESET:    "SAMCard hot reset",
		CRT571_PM_SAMCARD_CONTROL_AUTO_APDU:    "Auto distinguish T=0/T=1 CPUCard APDU data exchange",
		CRT571_PM_SAMCARD_CONTROL_STAND:        "Choose SAMCard stand",
	},

	CRT571_CM_SLE4442_4428_CARD_CONTROL: {
		CRT571_PM_SLE4442_4428_CARD_CONTROL_RESET:                "SLE4442/4428Card reset",
		CRT571_PM_SLE4442_4428_CARD_CONTROL_POWER_DOWN:           "SLE4442/4428Card power down",
		CRT571_PM_SLE4442_4428_CARD_CONTROL_CARD_STATUS:          "Browse SLE4442/4428Card status",
		CRT571_PM_SLE4442_4428_CARD_CONTROL_SLE4442_CARD_OPERATE: "Operate SLE4442Card",
		CRT571_PM_SLE4442_4428_CARD_CONTROL_SLE4428_CARD_OPERATE: "Operate SLE4428Card",
	},
	CRT571_CM_IIC_MEMORYCARD: {
		CRT571_PM_IIC_MEMORYCARD_RESET:      "IICCard reset",
		CRT571_PM_IIC_MEMORYCARD_POWER_DOWN: "IICCard down power",
		CRT571_PM_IIC_MEMORYCARD_STATUS:     "IICheck IICCard status",
		CRT571_PM_IIC_MEMORYCARD_READ:       "Read IICCard",
		CRT571_PM_IIC_MEMORYCARD_WRITE:      "Write IICCard",
	},
	CRT571_CM_RFCARD_CONTROL: {
		CRT571_PM_RFCARD_CONTROL_STARTUP:        "RF Card startup",
		CRT571_PM_RFCARD_CONTROL_POWER_DOWN:     "RF Card down power",
		CRT571_PM_RFCARD_CONTROL_STATUS:         "RF Card operation status check",
		CRT571_PM_RFCARD_CONTROL_CARD_RW:        "Mifare standard Card read/write",
		CRT571_PM_RFCARD_CONTROL_TYPEA_APDU:     "Type A standard T=CLCard APDU data exchange",
		CRT571_PM_RFCARD_CONTROL_TYPEB_APDU:     "Type B standard T=CLCard APDU data exchange",
		CRT571_PM_RFCARD_CONTROL_ENABLE_DISABLE: "RF Card enable/disable",
	},
	CRT571_CM_CARD_SERIAL_NUMBER: {
		CRT571_PM_CARD_SERIAL_NUMBER_READ: "Read Card Serial number",
	},
	CRT571_CM_READ_CARD_CONFIG: {
		CRT571_PM_READ_CARD_CONFIG: "Read Card configuration information",
	},
	CRT571_CM_READ_CRT571_VERSION: {
		CRT571_PM_READ_CRT571_VERSION: "Read Card software version information",
	},
	CRT571_CM_RECYCLEBIN_COUNTER: {
		CRT571_PM_RECYCLEBIN_COUNTER_READ:     "Read number of counter of Card error card bin",
		CRT571_PM_RECYCLEBIN_COUNTER_INITIATE: "Initiate card error card bin counter",
	},
}

var CRT571Errors = map[string]string{
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

type CRT571Service struct {
	config  CRT571Config
	port    *rs232.SerialPort
	address byte
}

type CRT571Config struct {
	BaudRate    int
	Path        string
	Address     int
	ReadTimeout int // Read timeout in Millisecond
}

type CRT571Response struct {
	Type         byte
	CardStatus   []byte
	ST0Message   string
	ST1Message   string
	ST2Message   string
	ErrorCode    []byte
	ErrorMessage string
	DataLen      int
	Data         []byte
}

func (response *CRT571Response) String() string {
	switch response.Type {
	case CRT571_PMT: // Positve response
		return fmt.Sprintf("CRT-571 positive response: card status:['%s','%s','%s'], data:[%s]", response.ST0Message, response.ST1Message, response.ST2Message, response.Data)
	case CRT571_EMT: // Failed response
		return fmt.Sprintf("CRT-571 error response: %s(%s), data:[%s]", response.ErrorMessage, response.ErrorCode, response.Data)
	}
	return "Unexpected response type"
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
func (service *CRT571Service) request(cm, pm byte, data []byte) (*CRT571Response, error) {
	var response CRT571Response

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
		return nil, errors.New("[ERROR] Exceed max packet size for CRT-571")
	}

	buf, err := service.exchange(b.Bytes())
	if err != nil {
		return nil, err
	}

	datalen := int(binary.BigEndian.Uint16(buf[2:4]))
	response.DataLen = datalen
	response.Type = buf[4]

	switch response.Type {
	case CRT571_PMT: // Positve response
		response.CardStatus = buf[7:10]
		response.ST0Message = CRT571CardStatus["ST0"][buf[7]]
		response.ST1Message = CRT571CardStatus["ST1"][buf[8]]
		response.ST2Message = CRT571CardStatus["ST2"][buf[9]]
		response.Data = buf[10 : 10+datalen-6]
		log.Printf("[INFO] request(): Get positive response. Card status:[% x]=[%s;%s;%s] data:[% x]=[%[5]s]", response.CardStatus, response.ST0Message, response.ST1Message, response.ST2Message, response.Data)

		return &response, nil

	case CRT571_EMT, CRT571_EMT2: // Failed response
		response.Data = buf[9 : 9+datalen-5]
		response.ErrorCode = buf[6:8]
		response.ErrorMessage = CRT571Errors[string(buf[6:8])]
		log.Printf("[ERROR] request(): Get negative response. Card status:[% x] data:[% x]=[%[2]s]", response.ErrorCode, response.Data)
		return &response, errors.New(response.ErrorMessage)
	}

	return &response, errors.New(fmt.Sprintf("[ERROR] Unknow data response status [%x]", response.Type))
}

// Command request
func (service *CRT571Service) Command(command, pm byte) (*CRT571Response, error) {
	log.Printf("[INFO] Command:[%s] PM:[%x]", CRT571Commands[command], pm)

	res, err := service.request(command, pm, nil)
	if err != nil {
		log.Printf("[ERROR] Command:[%s] PM:[%x] Error: %v", CRT571Commands[command], CRT571PMInfo[command][pm], err)
		return res, err
	}
	log.Printf("[INFO] Command:[%s]: PM:[%x] Card status:[% x] data:[%s]", CRT571Commands[command], CRT571PMInfo[command][pm], res.CardStatus, res.Data)
	return res, nil
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
