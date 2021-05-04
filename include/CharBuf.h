/*
 * CharBuf.h
 */

#ifndef INCLUDE_CHARBUF_H_
#define INCLUDE_CHARBUF_H_

#include <stdlib.h>

typedef struct CharBuffer
{
  unsigned char *chars;
  size_t len;
} CharBuf;

/**
 * <pre>
 * Takes a struct CharBuf and allocates memory of len then sets CharBuf len to @pram[in] len.
 * </pre>
 *
 * @param[in] len Length of new char array
 *
 * @return the initialized CharBuf
 */
CharBuf newCharBuf(size_t len);

/**
 * <pre>
 * Takes a struct CharBuf and frees the memory allocation then sets the values to null and 0.
 * </pre>
 *
 * @param[in] buf The CharBuf to be freed and cleared
 *
 * @return freed and clear CharBuf buf
 */
void freeCharBuf(CharBuf * buf);

/**
 * <pre>
 * Takes a two CharBufs and compares them to each other to determine which is greater.
 * </pre>
 *
 * @param[in] buf1 CharBuf to be compared
 * @param[in] buf2 CharBuf to be compared
 *
 * @return 0 if the buffers contain the same bytes
 *        -1 if buf1 is less than buf2 and the buffers are the same length
 *         1 if buf2 is less than buf1 and the buffers are the same length
 *        -2 if buf1 is longer than buf2
 *         2 if buf2 is longer than buf1
 *        -3 if error
 */
int cmpCharBuf(CharBuf buf1, CharBuf buf2);

/**
 * <pre>
 * Secure memset and frees CharBuf buf.
 * <pre>
 *
 * @param[in] buf THe CharBuf to be secure memset and freed
 *
 * @return freed and clear CharBuf buf
 */
void secureFreeCharBuf(CharBuf * buf);

/**
 * <pre>
 * This function prints the contents of a CharBuf
 * </pre>
 *
 * @param[in] buf The charBuf containing the buffer to be printed
 * @param[in] format An integer indicating how to format the print:
 *                   0 as ascii characters
 *                   1 as hex characters
 *
 * @return 0 on success, 1 on error
 */
int printCharBuf(CharBuf buf, int format);

/**
 * <pre>
 * This function determines the index location of a char in char array buf.
 * </pre>
 *
 * @param[in] buf The CharBuf to be searched
 * @param[in] c The character to be searched for in buf
 * @param[in] index The index position to start the search of the char array
 * @param[in] direction Indicator to search left or right of index
 *                      0 to search right of index
 *                      1 to search left of index
 *
 * @return index if char is contained in buf
 *         -1 if char is not found or invalid inputs
 */
int getIndexForChar(CharBuf buf, char c, int index, int direction);

/**
 * <pre>
 * This function creates a new CharBuf that contains the contents of another buffer starting at 
 * the specified index
 * </pre>
 *
 * @param[in] buf The CharBuf to be copied from
 * @param[in] index The starting char of char array to be copied
 *
 * @return CharBuf copy of tail of buf starting at index
 */
CharBuf copyBytesFromBuf(CharBuf buf, int index);

/**
 * <pre>
 * This function creates a new CharBuf that contains the contents of two character strings
 * </pre>
 *
 * @param[in] prefix The character string of the key_id without current working directory prefix (schema notation)
 * @param[in] postfix The character string of the key_id without current working directory postfix (file path)
 *
 * @return CharBuf copy of key_id with current working directory
 */
CharBuf copyCWDToId(char *prefix, char postfix);

#endif /* INCLUDE_CHARBUF_H_ */
