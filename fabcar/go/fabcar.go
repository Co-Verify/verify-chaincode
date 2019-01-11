/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * The sample smart contract for documentation topic:
 * Writing Your First Blockchain Application
 */

package main

/* Imports
 * 4 utility libraries for formatting, handling bytes, reading and writing JSON, and string manipulation
 * 2 specific Hyperledger Fabric specific libraries for Smart Contracts
 */
import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/jmoiron/jsonq"
	"strconv"
	"strings"

	"github.com/cd1/utils-golang"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
)

// Define the Smart Contract structure
type SmartContract struct {
}

type User struct {
	Doctype string
	Name string
	Email string
	PasswordHash string
	Token string
	Key string
}

type Document struct {
	Doctype string
	DocHash string
	DocName string
	OwnerKey string
}

type Signature struct {
	Doctype string
	DocHash string
	Signature string
	StatusCode string
	Message string
	SignerKey string
}

type Request struct {
	Doctype string
	DocumentName string
	DocumentKey string
	SenderKey string
	SenderEmail string
	ReceiverKey string
	SignStatus bool
}

type CouchQueryBuilder struct {
	Start string
	SelectorStart string
	SelectorBody string
	SelectorEnd string
	End string
}

func newCouchQueryBuilder() *CouchQueryBuilder {
	return &CouchQueryBuilder{Start:"{", SelectorStart:"\"selector\":{", SelectorBody:"", SelectorEnd:"}", End:"}"}
}

func (q *CouchQueryBuilder) addSelector(key string, value interface{}) *CouchQueryBuilder {
	if q.SelectorBody != "" {
		q.SelectorBody = q.SelectorBody + ","
	}
	var addedString string
	switch v := value.(type) {
	case string:
		addedString = fmt.Sprintf("\"%s\":\"%v\"", key, value)
	case []byte:
		addedString = fmt.Sprintf("\"%s\":\"%v\"", key, value)
	default:
		addedString = fmt.Sprintf("\"%s\":%v", key, value)
		fmt.Printf("%q", v)
	}
	q.SelectorBody = q.SelectorBody + addedString
	return q
}

func (q *CouchQueryBuilder) addSelectorWithOperator(key string, operator string, value interface{}) *CouchQueryBuilder {
	if q.SelectorBody != "" {
		q.SelectorBody = q.SelectorBody + ","
	}
	var addedString string
	switch v := value.(type) {
	case string:
		addedString = fmt.Sprintf("\"%s\":{\"%s\":\"%s\"}", key, operator, value)
	case []byte:
		addedString = fmt.Sprintf("\"%s\":{\"%s\":\"%s\"}", key, operator, value)
	default:
		addedString = fmt.Sprintf("\"%s\":{\"%s\":%v}", key, operator, value)
		fmt.Printf("%q", v)
	}
	q.SelectorBody = q.SelectorBody + addedString
	return q
}

func (q *CouchQueryBuilder) getQueryString() string {
	return q.Start + q.SelectorStart + q.SelectorBody + q.SelectorEnd + q.End
}

type QueryResponse struct {
	Key string
	Record []byte
	Query *jsonq.JsonQuery
}

func decodeSingleResponse(jsonResponse []byte) *QueryResponse {
	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(jsonResponse)))
	err := dec.Decode(&data)
	if err!=nil {
		fmt.Println(err.Error())
	}
	jq := jsonq.NewQuery(data)

	key, err := jq.String("Key")
	if err!=nil {
		fmt.Println(err.Error())
	}
	record, err := jq.String("Record")
	if err!=nil {
		fmt.Println(err.Error())
	}
	recordByteArray := []byte(record)

	return &QueryResponse{Key: key , Record: recordByteArray, Query: jq }
}

/*
 * The Init method is called when the Smart Contract "fabcar" is instantiated by the blockchain network
 * Best practice is to have any Ledger initialization in separate function -- see initLedger()
 */
func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

/*
 * The Invoke method is called as a result of an application request to run the Smart Contract "fabcar"
 * The calling application program has also specified the particular smart contract function to be called, with arguments
 */
func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {

	// Retrieve the requested Smart Contract function and arguments
	function, args := APIstub.GetFunctionAndParameters()
	// Route to the appropriate handler function to interact with the ledger appropriately
	if function == "register" {
		return s.register(APIstub, args)
	} else if function == "login" {
		return s.login(APIstub, args)
	} else if function == "logout" {
		return s.logout(APIstub, args)
	} else if function == "uploadDocument" {
		return s.uploadDocument(APIstub, args)
	} else if function == "getData" {
		return s.getDataFromArgs(APIstub, args)
	} else if function == "setData" {
		return s.setData(APIstub, args)
	} else if function == "putObject" {
		return s.putObject(APIstub, args)
	} else if function == "getObject" {
		return s.getObject(APIstub, args)
	} else if function == "listRequests" {
		return s.listRequests(APIstub, args)
	} else if function == "listDocuments" {
		return s.listDocuments(APIstub, args)
	} else if function == "checkSignature" {
		return s.checkSignature(APIstub, args)
	} else if function == "signDoc" {
		return s.signDoc(APIstub, args)
	} else if function == "requestForSignature" {
		return s.requestForSignature(APIstub, args)
	}

	return shim.Error("Invalid Smart Contract function name.")
}

func (s *SmartContract) getKeyFromToken(APIstub shim.ChaincodeStubInterface, token string) string {
	//queryString := fmt.Sprintf("{\"selector\":{\"Doctype\":\"user\",\"Token\":\"%s\"}}", token)
	queryString := newCouchQueryBuilder().addSelector("Doctype", "user").addSelector("Token", token).getQueryString()
	fmt.Println("Query String: ", queryString)

	jsonResponse, err := firstQueryResultForQueryString(APIstub, queryString)
	if err!=nil {
		fmt.Printf("Error Occured")
		panic(err)
	}

	response := decodeSingleResponse(jsonResponse)
	fmt.Println(jsonResponse);

	//[{"Key":"YvSgD5xAV0", "Record":{"Doctype":"user","Email":"tanmoykrishnadas@gmail.com","Key":"YvSgD5xAV0","Name":"Tanmoy Krishna Das","PasswordHash":"ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f","Token":"Bd56ti2SMt"}}]

	key := response.Key
	return key
}

func (s *SmartContract) listRequests(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]

	key := s.getKeyFromToken(APIstub, token)

	documentQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"request\",\"SignStatus\": false,\"ReceiverKey\":\"%s\"}}", key)
	jsonData, err := getQueryResultForQueryString(APIstub, documentQuery)
	if err!=nil {
		fmt.Println(err.Error())
	}

	return shim.Success(jsonData)
}

func (s *SmartContract) listDocuments(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]

	key := s.getKeyFromToken(APIstub, token)

	documentQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"document\",\"OwnerKey\": \"%s\"}}", key)
	jsonData, err := getQueryResultForQueryString(APIstub, documentQuery)
	if err!=nil {
		fmt.Println(err.Error())
	}

	return shim.Success(jsonData)
}

func (s *SmartContract) checkSignature(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	docHash := args[1]

	key := s.getKeyFromToken(APIstub, token)

	documentQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"document\",\"OwnerKey\": \"%s\", \"DocHash\": \"%s\"}}", key, docHash)
	jsonData, err := getQueryResultForQueryString(APIstub, documentQuery)
	if err!=nil {
		fmt.Println(err.Error())
	}

	return shim.Success(jsonData)
}

func (s *SmartContract) signDoc(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	docHash := args[1]
	message := "Attested"
	signStatus := true

	key := s.getKeyFromToken(APIstub, token)

	signature := Signature{"signature", docHash, message, message, message, key}
	signatureKey := utils.RandomString()
	jsonSignature, err := json.Marshal(signature)
	err = APIstub.PutState(signatureKey, jsonSignature)
	if err!=nil {
		fmt.Println("signing error")
	}

	//senderKey := s.getKeyFromToken(APIstub, token)

	documentQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"request\",\"DocHash\":\"%s\",\"ReceiverKey\":\"%s\"}}", docHash, key)
	jsonData, err := firstQueryResultForQueryString(APIstub, documentQuery)

	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(jsonData)))
	err = dec.Decode(&data)
	if err!=nil {
		fmt.Println(err.Error())
	}
	jq := jsonq.NewQuery(data)
	documentKey, err := jq.String("Key")
	documentData, err := jq.String("Record")


	var request Request
	_ = json.Unmarshal([]byte(documentData), &request)
	request.SignStatus = signStatus
	newDocumentData, _ := json.Marshal(request)
	err = APIstub.PutState(documentKey, newDocumentData)
	if err!=nil {
		fmt.Println("signing error")
	}

	return shim.Success(nil)
}

func (s *SmartContract) requestForSignature(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	docHash := args[1]
	emailOfSigner := args[2]

	senderKey := s.getKeyFromToken(APIstub, token)

	queryString := fmt.Sprintf("{\"selector\":{\"Doctype\":\"document\",\"DocHash\":\"%s\",\"OwnerKey\":\"%s\"}}", docHash, senderKey)

	jsonData, err := firstQueryResultForQueryString(APIstub, queryString)

	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(jsonData)))
	err = dec.Decode(&data)
	if err!=nil {
		fmt.Println(err.Error())
	}
	jq := jsonq.NewQuery(data)

	documentName, err := jq.String("Record", "DocumentName")
	if err!=nil {
		fmt.Println(err.Error())
	}
	documentKey, err := jq.String("Key")


	receiverQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"user\",\"Email\":\"%s\"}}", emailOfSigner)
	jsonData, err = firstQueryResultForQueryString(APIstub, receiverQuery)

	data = map[string]interface{}{}
	dec = json.NewDecoder(strings.NewReader(string(jsonData)))
	err = dec.Decode(&data)
	if err!=nil {
		fmt.Println(err.Error())
	}
	jq = jsonq.NewQuery(data)

	receiverKey, err := jq.String("Key")

	senderQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"user\",\"Key\":\"%s\"}}", senderKey)
	jsonData, err = firstQueryResultForQueryString(APIstub, senderQuery)

	data = map[string]interface{}{}
	dec = json.NewDecoder(strings.NewReader(string(jsonData)))
	err = dec.Decode(&data)
	if err!=nil {
		fmt.Println(err.Error())
	}
	jq = jsonq.NewQuery(data)
	senderEmail, err := jq.String("Record", "Email")

	request := Request{"request", documentName, documentKey, senderKey, senderEmail, receiverKey, false}

	jsonRequest, err := json.Marshal(request)

	requestKey := utils.RandomString()
	err = APIstub.PutState(requestKey, jsonRequest)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (s *SmartContract) uploadDocument(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments, required 3, given "+strconv.Itoa(len(args)))
	}

	ownerToken := args[0]
	docName := args[1]
	docHash := args[2]

	ownerKey := s.getKeyFromToken(APIstub, ownerToken)

	document := Document{"document", docHash, docName, ownerKey}

	jsonDoc, err := json.Marshal(document)
	if err!=nil {
		return shim.Error(err.Error())
	}

	err = APIstub.PutState(docHash, jsonDoc)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

// =========================================================================================
// getQueryResultForQueryString executes the passed in query string.
// Result set is built and returned as a byte array containing the JSON results.
// =========================================================================================
func getQueryResultForQueryString(stub shim.ChaincodeStubInterface, queryString string) ([]byte, error) {

	fmt.Printf("- getQueryResultForQueryString queryString:\n%s\n", queryString)

	resultsIterator, err := stub.GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	buffer, err := constructQueryResponseFromIterator(resultsIterator)
	if err != nil {
		return nil, err
	}

	fmt.Printf("- getQueryResultForQueryString queryResult:\n%s\n", buffer.String())

	return buffer.Bytes(), nil
}

// ===========================================================================================
// constructQueryResponseFromIterator constructs a JSON array containing query results from
// a given result iterator
// ===========================================================================================
func constructQueryResponseFromIterator(resultsIterator shim.StateQueryIteratorInterface) (*bytes.Buffer, error) {
	// buffer is a JSON array containing QueryResults
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	return &buffer, nil
}

func firstQueryResultForQueryString(stub shim.ChaincodeStubInterface, queryString string) ([]byte, error) {

	fmt.Printf("- getQueryResultForQueryString queryString:\n%s\n", queryString)

	resultsIterator, err := stub.GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	buffer, err := firstQueryResponseFromIterator(resultsIterator)
	if err != nil {
		return nil, err
	}

	fmt.Printf("- getQueryResultForQueryString queryResult:\n%s\n", buffer.String())

	return buffer.Bytes(), nil
}

// ===========================================================================================
// firstQueryResponseFromIterator returns query results from
// a given result iterator
// ===========================================================================================
func firstQueryResponseFromIterator(resultsIterator shim.StateQueryIteratorInterface) (*bytes.Buffer, error) {
	// buffer is a JSON array containing QueryResults
	var buffer bytes.Buffer

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true

		break
	}

	return &buffer, nil
}

func (s *SmartContract) register(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments, required 3, given "+strconv.Itoa(len(args)))
	}

	name := args[0]
	email := args[1]
	password := args[2]

	h := sha256.New()
	h.Write([]byte(password))
	passwordHash := fmt.Sprintf("%x", h.Sum(nil))

	token := utils.RandomString()

	key := utils.RandomString()

	user := User{"user", name, email, passwordHash, token, key}
	jsonUser, err := json.Marshal(user)
	if err!=nil {
		return shim.Error(err.Error())
	}

	err = APIstub.PutState(key, jsonUser)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success([]byte(token))
}

func (s *SmartContract) logout(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments, required 1, given "+strconv.Itoa(len(args)))
	}

	key := args[0]
	var user User

	jsonUser, err := APIstub.GetState(key)
	if err!=nil {
		return shim.Error(err.Error())
	}

	err = json.Unmarshal(jsonUser, &user)
	if err != nil {
		return shim.Error(err.Error())
	}

	user.Token = utils.RandomString()

	jsonUser, err = json.Marshal(user)
	if err!=nil {
		return shim.Error(err.Error())
	}

	err = APIstub.PutState(key, jsonUser)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (s *SmartContract) login(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments, required 2, given "+strconv.Itoa(len(args)))
	}

	email := args[0]
	password := args[1]

	h := sha256.New()
	h.Write([]byte(password))
	passwordHash := fmt.Sprintf("%x", h.Sum(nil))

	queryString := fmt.Sprintf("{\"selector\":{\"Doctype\":\"user\",\"Email\":\"%s\",\"PasswordHash\":\"%s\"}}", email, passwordHash)

	jsonData, err := getQueryResultForQueryString(APIstub, queryString)
	if err != nil {
		return shim.Error(err.Error())
	}

	value := string(jsonData)

	// Take substring of first word with runes.
	// ... This handles any kind of rune in the string.
	runes := []rune(value)
	// ... Convert back into a string from rune slice.
	safeSubstring := string(runes[1:len(runes)-1])

	fmt.Println(safeSubstring)

	jsonData = []byte(safeSubstring)

	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(jsonData)))
	err = dec.Decode(&data)
	if err!=nil {
		fmt.Println(err.Error())
	}
	jq := jsonq.NewQuery(data)

	//[{"Key":"YvSgD5xAV0", "Record":{"Doctype":"user","Email":"tanmoykrishnadas@gmail.com","Key":"YvSgD5xAV0","Name":"Tanmoy Krishna Das","PasswordHash":"ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f","Token":"Bd56ti2SMt"}}]

	token, err := jq.String("Record", "Token")
	key, err := jq.String("Record", "Key")
	if err!=nil {
		fmt.Println(err.Error())
	}

	jsonResult:= fmt.Sprintf("{\"token\" : \"%s\" , \"key\" : \"%s\"}", token, key)

	return shim.Success([]byte(jsonResult))
}

func (s *SmartContract) getData(APIstub shim.ChaincodeStubInterface, args ...string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	key := args[0]

	data, err := APIstub.GetState(key)
	if err != nil {
		return shim.Error("There was an error")
	}

	return shim.Success(data)
}

func (s *SmartContract) getDataFromArgs(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	key := args[0]

	data, err := APIstub.GetState(key)
	if err != nil {
		return shim.Error("There was an error")
	}

	return shim.Success(data)
}

func (s *SmartContract) setData(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	key := args[0]
	val := args[1]

	err := APIstub.PutState(key, []byte(val))
	if err != nil {
		return shim.Error("There was an error")
	}

	str := "operation successful"

	return shim.Success([]byte(str))
}

func MockInvoke(stub *shim.MockStub, function string, args []string) sc.Response {
	input := args
	output := make([][]byte, len(input)+1)
	output[0]= []byte(function)
	for i, v := range input {
		output[i+1] = []byte(v)
	}

	fmt.Println("final arguments: ", output) // [[102 111 111] [98 97 114]]

	return stub.MockInvoke("1", output)
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {
	//scc := new(SmartContract)
	//stub := shim.NewMockStub("mychannel", scc)
	//res := MockInvoke(stub, "register", []string {"Tanmoy Krishna Das", "tanmoykrishnadas@gmail.com", "12345678"})
	//if res.Status != shim.OK {
	//	fmt.Println("bad status received, expected: 200; received:" + strconv.FormatInt(int64(res.Status), 10))
	//	fmt.Println("response: " + string(res.Message))
	//}
	//fmt.Println("Payload", string(res.Payload))
	//fmt.Println("Message", res.Message)

	//res = MockInvoke(stub, "login", []string {"tanmoykrishnadas@gmail.com", "12345678"})
	//if res.Status != shim.OK {
	//	fmt.Println("bad status received, expected: 200; received:" + strconv.FormatInt(int64(res.Status), 10))
	//	fmt.Println("response: " + string(res.Message))
	//}
	//fmt.Println("Payload", string(res.Payload))
	//fmt.Println("Message", res.Message)

	// Create a new Smart Contract
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating new Smart Contract: %s", err)
	}
}
