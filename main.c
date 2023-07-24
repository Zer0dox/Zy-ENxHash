#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <bcrypt.h>
#include <pthread.h>

// Function to generate an SHA-1 hash for a given input string
void generateSHA1Hash(const char *input, char *output) {

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", (unsigned int)digest[i]);
    }
    output[SHA_DIGEST_LENGTH * 2] = '\0';
}

// Function to generate an SHA-256 hash for a given input string
void generateSHA256Hash(const char *input, char *output) {'
'
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", (unsigned int)digest[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Function to generate an SHA-512 hash for a given input string
void generateSHA512Hash(const char *input, char *output) {

    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", (unsigned int)digest[i]);
    }
    output[SHA512_DIGEST_LENGTH * 2] = '\0';

}

// Structure to hold data for a thread
struct ThreadData {
    const char *hashType;
    char **hashes;
    const char *filename;
    int startLine;
    int endLine;
    const char *hashToCompare;
    int *matchFound;
};

// Thread function to read file lines and generate hashes
void *generateHashesThread(void *arg) {

    struct ThreadData *threadData = (struct ThreadData *)arg;

    int lineCount = 0;
    char buffer[256];

    FILE *file = fopen(threadData->filename, "r");
    if (file == NULL) {
        printf("Error opening file: %s\n", threadData->filename);
        return NULL;
    }

    // Move to the start line for this thread
    for (int i = 0; i < threadData->startLine; i++) {
        if (fgets(buffer, sizeof(buffer), file) == NULL) {
            break;
        }
    }

    // Read and process lines within the thread's range
    while (lineCount < (threadData->endLine - threadData->startLine)) {
        if (fgets(buffer, sizeof(buffer), file) == NULL) {
            break;
        }

        buffer[strcspn(buffer, "\n")] = '\0'; // Remove the newline character

        if (strcmp(threadData->hashType, "md5") == 0) {
            generateMD5Hash(buffer, threadData->hashes[threadData->startLine + lineCount]);
        } else if (strcmp(threadData->hashType, "sha1") == 0) {
            generateSHA1Hash(buffer, threadData->hashes[threadData->startLine + lineCount]);
        } else if (strcmp(threadData->hashType, "sha256") == 0) {
            generateSHA256Hash(buffer, threadData->hashes[threadData->startLine + lineCount]);
        } else if (strcmp(threadData->hashType, "bcrypt") == 0) {
            generateBcryptHash(buffer, threadData->hashes[threadData->startLine + lineCount]);
        } else {
            printf("Unsupported hash type: %s\n", threadData->hashType);
            fclose(file);
            return NULL;
        }

        lineCount++;
    }

        fclose(file);
        
    // Append numbers 1 to 9999 to each line and generate hashes
    for (int i = threadData->startLine; i < threadData->endLine; i++) {
        char buffer[256];
        sprintf(buffer, "%s%d", input, i + 1); // Append the number to the line

        if (strcmp(threadData->hashType, "md5") == 0) {
            generateMD5Hash(buffer, threadData->hashes[i]);
        } else if (strcmp(threadData->hashType, "sha1") == 0) {
            generateSHA1Hash(buffer, threadData->hashes[i]);
        } else if (strcmp(threadData->hashType, "sha256") == 0) {
            generateSHA256Hash(buffer, threadData->hashes[i]);
        } else if (strcmp(threadData->hashType, "bcrypt") == 0) {
            generateBcryptHash(buffer, threadData->hashes[i]);
        } else if (strcmp(threadData->hashType, "sha512") == 0) {
            generateSHA512Hash(buffer, threadData->hashes[i]);
        } else {
            printf("Unsupported hash type: %s\n", threadData->hashType);
            return NULL;
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    
    if (argc != 6) {
        printf("Usage: %s <filename> <hash_type> <max_lines> <num_threads> <hash_to_compare>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *hashType = argv[2];
    int maxLines = atoi(argv[3]);
    int numThreads = atoi(argv[4]);
    const char *hashToCompare = argv[5];
    int matchFound = 0;

    char **hashes = (char **)malloc(maxLines * sizeof(char *));
    for (int i = 0; i < maxLines; i++) {
        hashes[i] = (char *)malloc(129 * sizeof(char));
    }

    // Create threads to generate hashes
    pthread_t threads[numThreads];
    struct ThreadData threadData[numThreads];

    int linesPerThread = maxLines / numThreads;

    for (int i = 0; i < numThreads; i++) {
        threadData[i].hashType = hashType;
        threadData[i].hashes = hashes;
        threadData[i].filename = filename;
        threadData[i].startLine = i * linesPerThread;
        threadData[i].endLine = (i == (numThreads - 1)) ? maxLines : (i + 1) * linesPerThread;
        threadData[i].hashToCompare = hashToCompare;
        threadData[i].matchFound = &matchFound;

        pthread_create(&threads[i], NULL, generateHashesThread, &threadData[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    if (matchFound) {
        printf("Hash match found for %s!\n", hashToCompare);
    } else {
        printf("Hash not found for %s.\n", hashToCompare);
    }

    // Free dynamically allocated memory
    for (int i = 0; i < maxLines; i++) {
        free(hashes[i]);
    }
    free(hashes);

    return 0;
}