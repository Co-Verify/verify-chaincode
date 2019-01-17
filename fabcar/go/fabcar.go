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
	"encoding/json"
	"fmt"
	"github.com/cd1/utils-golang"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
	"github.com/jmoiron/jsonq"
	"strconv"
	"strings"
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
	EncryptedPrivateKey string
	PublicKey string
}

type Document struct {
	Doctype string
	DocHash string
	DocName string
	DocPath string
	OwnerKey string
	Key string
}

type Signature struct {
	Doctype string
	DocKey string
	DocHash string
	Signature string
	StatusCode string
	Message string
	SignerKey string
	SignerPublicKey string
	Key string
}

type Request struct {
	Doctype string
	DocumentName string
	DocumentKey string
	DocumentHash string
	DocumentPath string
	SenderKey string
	SenderName string
	SenderEmail string
	ReceiverKey string
	ReceiverName string
	ReceiverEmail string
	SignStatus bool
	Key string
}

type Share struct {
	Doctype string
	DocumentName string
	DocumentPath string
	ReceiverKey string
	SenderMail string
	SenderName string
	Key string
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
	} else if function == "listDocuments" {
		return s.listDocuments(APIstub, args)
	} else if function == "requestForSignature" {
		return s.requestForSignature(APIstub, args)
	} else if function == "myReq" {
		return s.myReq(APIstub, args)
	} else if function == "shareDocument" {
		return s.shareDocument(APIstub, args)
	} else if function == "getShares" {
		return s.getShares(APIstub, args)
	} else if function == "listIncomingRequests" {
		return s.listIncomingRequests(APIstub, args)
	} else if function == "getUserFromToken" {
		return s.getUserFromToken(APIstub, args)
	} else if function == "checkSignature" {
		return s.checkSignature(APIstub, args)
	} else if function == "signDoc" {
		return s.signDoc(APIstub, args)
	} else if function == "getSignatures" {
		return s.getSignatures(APIstub, args);
	}
	return shim.Error("Invalid Smart Contract function name.")
}

func (s *SmartContract) getKeyFromToken(APIstub shim.ChaincodeStubInterface, token string) string {
	queryString := newCouchQueryBuilder().addSelector("Doctype", "user").addSelector("Token", token).getQueryString()
	fmt.Println("Query String: ", queryString)

	jsonResponse, err := firstQueryResultForQueryString(APIstub, queryString)
	if err!=nil {
		fmt.Printf("Error Occured")
		panic(err)
	}
	response := decodeSingleResponse(jsonResponse)

	key := response.Key
	return key
}

func (s *SmartContract) listIncomingRequests(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args)!=1 {
		return shim.Error("Incorrect number of arguments, required 1, given "+strconv.Itoa(len(args)))
	}
	token := args[0]
	key := s.getKeyFromToken(APIstub, token)

	//documentQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"request\",\"SignStatus\": false,\"ReceiverKey\":\"%s\"}}", key)
	documentQuery := newCouchQueryBuilder().addSelector("Doctype", "request").addSelector("SignStatus", false).addSelector("ReceiverKey", key).addSelector("SignStatus", false).getQueryString()
	jsonData, err := getJSONQueryResultForQueryString(APIstub, documentQuery)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(jsonData)
}

func (s *SmartContract) listDocuments(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]

	key := s.getKeyFromToken(APIstub, token)

	//documentQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"document\",\"OwnerKey\": \"%s\"}}", key)
	documentQuery := newCouchQueryBuilder().addSelector("Doctype", "document").addSelector("OwnerKey", key).getQueryString()
	jsonData, err := getJSONQueryResultForQueryString(APIstub, documentQuery)
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
	docKey := args[1]
	message := args[2]
	sign := args[3]
	docHash := args[4]

	signStatus := true

	key := s.getKeyFromToken(APIstub, token)

	jsonUser, _ := APIstub.GetState(key)
	var user User
	_ = json.Unmarshal(jsonUser, &user)


	signatureKey := utils.RandomString()
	signature := Signature{"signature", docKey, docHash, sign, message, message, key, user.PublicKey, signatureKey}

	jsonSignature, err := json.Marshal(signature)
	err = APIstub.PutState(signatureKey, jsonSignature)
	if err!=nil {
		fmt.Println("signing error")
	}

	//senderKey := s.getKeyFromToken(APIstub, token)


	//documentQuery := fmt.Sprintf("{\"selector\":{\"Doctype\":\"request\",\"DocHash\":\"%s\",\"ReceiverKey\":\"%s\"}}", docKey, key)
	documentQuery := newCouchQueryBuilder().addSelector("Doctype", "request").addSelector("DocumentHash", docHash).addSelector("ReceiverKey", key).addSelector("DocumentKey", docKey).getQueryString()
	documentData, _ := firstQueryValueForQueryString(APIstub, documentQuery)

	//jsonData, err := firstQueryResultForQueryString(APIstub, documentQuery)
	//
	//data := map[string]interface{}{}
	//dec := json.NewDecoder(strings.NewReader(string(jsonData)))
	//err = dec.Decode(&data)
	//if err!=nil {
	//	fmt.Println(err.Error())
	//}
	//jq := jsonq.NewQuery(data)
	//documentKey, err := jq.String("Key")
	//documentData, err := jq.String("Record")

	var request Request
	_ = json.Unmarshal(documentData, &request)
	request.SignStatus = signStatus
	newDocumentData, _ := json.Marshal(request)
	err = APIstub.PutState(request.Key, newDocumentData)
	if err!=nil {
		fmt.Println("signing error")
	}

	return shim.Success(nil)
}

func (s *SmartContract) requestForSignature(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	docKey := args[1]
	emailOfSigner := args[2]

	senderKey := s.getKeyFromToken(APIstub, token)

	queryString := newCouchQueryBuilder().addSelector("Doctype", "document").addSelector("Key", docKey).addSelector("OwnerKey", senderKey).getQueryString()
	jsonData, err := firstQueryValueForQueryString(APIstub, queryString)
	var document Document
	_ = json.Unmarshal(jsonData, &document)

	receiverQuery := newCouchQueryBuilder().addSelector("Doctype", "user").addSelector("Email", emailOfSigner).getQueryString()
	jsonData, err = firstQueryValueForQueryString(APIstub, receiverQuery)
	var receiver User
	_ = json.Unmarshal(jsonData, &receiver)

	senderQuery := newCouchQueryBuilder().addSelector("Doctype", "user").addSelector("Key", senderKey).getQueryString()
	jsonData, err = firstQueryValueForQueryString(APIstub, senderQuery)
	var sender User
	_ = json.Unmarshal(jsonData, &sender)


	requestKey := utils.RandomString()
	request := Request{"request", document.DocName, document.Key, document.DocHash, document.DocPath, sender.Key, sender.Name, sender.Email, receiver.Key, receiver.Name, receiver.Email, false, requestKey}

	jsonRequest, err := json.Marshal(request)

	err = APIstub.PutState(requestKey, jsonRequest)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (s *SmartContract) uploadDocument(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 4 {
		return shim.Error("Incorrect number of arguments, required 3, given "+strconv.Itoa(len(args)))
	}

	ownerToken := args[0]
	docName := args[1]
	docHash := args[2]
	docPath := args[3]

	//return shim.Success(nil)
	//ownerKey := ownerToken
	ownerKey := s.getKeyFromToken(APIstub, ownerToken)

	documentKey := utils.RandomString()
	document := Document{"document", docHash, docName, docPath, ownerKey, documentKey}

	jsonDoc, err := json.Marshal(document)
	if err!=nil {
		return shim.Error(err.Error())
	}

	err = APIstub.PutState(documentKey, jsonDoc)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func (s *SmartContract) register(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	if len(args) != 5 {
		return shim.Error("Incorrect number of arguments, required 3, given "+strconv.Itoa(len(args)))
	}

	name := args[0]
	email := args[1]
	password := args[2]
	encPrivKey := args[3]
	pubKey := args[4]

	token := utils.RandomString()

	key := utils.RandomString()

	user := User{"user", name, email, password, token, key, encPrivKey, pubKey}
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

	token := args[0]
	key := s.getKeyFromToken(APIstub, token)
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

	//h := sha256.New()
	//h.Write([]byte(password))
	//passwordHash := fmt.Sprintf("%x", h.Sum(nil))

	queryString := fmt.Sprintf("{\"selector\":{\"Doctype\":\"user\",\"Email\":\"%s\",\"PasswordHash\":\"%s\"}}", email, password)

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

func (s *SmartContract) getSignatures(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	docKey := args[0]
	documentQuery := newCouchQueryBuilder().addSelector("Doctype", "signature").addSelector("DocKey", docKey).getQueryString()
	jsonData, err := getJSONQueryResultForQueryString(APIstub, documentQuery)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(jsonData)
}

func (s *SmartContract) myReq(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	senderKey := s.getKeyFromToken(APIstub, token)
	documentQuery := newCouchQueryBuilder().addSelector("Doctype", "request").addSelector("SenderKey", senderKey).getQueryString()
	jsonData, err := getJSONQueryResultForQueryString(APIstub, documentQuery)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(jsonData)
}

func (s *SmartContract) getShares(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	senderKey := s.getKeyFromToken(APIstub,token)

	shareQuery := newCouchQueryBuilder().addSelector("Doctype", "share").addSelector("ReceiverKey", senderKey).getQueryString()
	jsonShares, _ := getJSONQueryResultForQueryString(APIstub, shareQuery)

	return shim.Success(jsonShares)
}

func (s *SmartContract) shareDocument(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	receiverEmail := args[1]
	documentKey := args[2]

	senderKey := s.getKeyFromToken(APIstub,token)

	receiverQuery := newCouchQueryBuilder().addSelector("Doctype", "user").addSelector("Email", receiverEmail).getQueryString()
	jsonData, _ := firstQueryValueForQueryString(APIstub, receiverQuery)
	var receiver User
	_ = json.Unmarshal(jsonData, &receiver)

	senderQuery := newCouchQueryBuilder().addSelector("Doctype", "user").addSelector("Key", senderKey).getQueryString()
	jsonSenderData, _ := firstQueryValueForQueryString(APIstub, senderQuery)
	var sender User
	_ = json.Unmarshal(jsonSenderData, &sender)

	documentQuery := newCouchQueryBuilder().addSelector("Doctype", "document").addSelector("Key", documentKey).getQueryString()
	jsonDocumentData, _ := firstQueryValueForQueryString(APIstub, documentQuery)
	var document Document
	_ = json.Unmarshal(jsonDocumentData, &document)

	share := Share{"share", document.DocName, document.DocPath, receiver.Key, sender.Email, sender.Name, utils.RandomString()}
	jsonShare, _ := json.Marshal(share)
	err := APIstub.PutState(share.Key, jsonShare)
	if err!=nil {
		return shim.Error(err.Error())
	}
	return shim.Success(jsonShare)
}

func (s *SmartContract) getUserFromToken(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	token := args[0]
	userKey := s.getKeyFromToken(APIstub,token)
	jsonUser, _ := APIstub.GetState(userKey)
	return shim.Success(jsonUser)
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
