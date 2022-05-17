#ifndef __PERSISTENCE_H__
#define __PERSISTENCE_H__

typedef enum
{
    None = 0,
    User,
    System,
    Both
} PersistenceType;

size_t executeCommand(const char* command, char* output, size_t size);
unsigned int isPersistent(char* bin);
unsigned int installPersistence(char* bin, PersistenceType type);
unsigned int removePersistence(char* bin, PersistenceType type);

enum OSType
{
    none,
    centos,
    ubuntu,
    arch,
    macos
};

#endif
