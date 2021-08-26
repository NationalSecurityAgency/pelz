/*
 * charbuf.h
 */

#ifndef INCLUDE_CHARBUF_H_
#define INCLUDE_CHARBUF_H_

#include <stdlib.h>

typedef struct charbuffer
{
  unsigned char *chars;
  size_t len;
} charbuf;

/**
 * <pre>
 * Takes a struct charbuf and allocates memory of len then sets charbuf len to @pram[in] len.
 * </pre>
 *
 * @param[in] len Length of new char array
 *
 * @return the initialized charbuf
 */
charbuf new_charbuf(size_t len);

/**
 * <pre>
 * Takes a struct charbuf and frees the memory allocation then sets the values to null and 0.
 * </pre>
 *
 * @param[in] buf The charbuf to be freed and cleared
 *
 * @return freed and clear charbuf buf
 */
void free_charbuf(charbuf * buf);

/**
 * <pre>
 * Takes a two charbufs and compares them to each other to determine which is greater.
 * </pre>
 *
 * @param[in] buf1 charbuf to be compared
 * @param[in] buf2 charbuf to be compared
 *
 * @return 0 if the buffers contain the same bytes
 *        -1 if buf1 is less than buf2 and the buffers are the same length
 *         1 if buf2 is less than buf1 and the buffers are the same length
 *        -2 if buf1 is longer than buf2
 *         2 if buf2 is longer than buf1
 *        -3 if error
 */
int cmp_charbuf(charbuf buf1, charbuf buf2);

/**
 * <pre>
 * Secure memset and frees charbuf buf.
 * <pre>
 *
 * @param[in] buf THe charbuf to be secure memset and freed
 *
 * @return freed and clear charbuf buf
 */
void secure_free_charbuf(charbuf * buf);

/**
 * <pre>
 * This function prints the contents of a charbuf
 * </pre>
 *
 * @param[in] buf The charBuf containing the buffer to be printed
 * @param[in] format An integer indicating how to format the print:
 *                   0 as ascii characters
 *                   1 as hex characters
 *
 * @return 0 on success, 1 on error
 */
int printcharbuf(charbuf buf, int format);

/**
 * <pre>
 * This function determines the index location of a char in char array buf.
 * </pre>
 *
 * @param[in] buf The charbuf to be searched
 * @param[in] c The character to be searched for in buf
 * @param[in] index The index position to start the search of the char array
 * @param[in] direction Indicator to search left or right of index
 *                      0 to search right of index
 *                      1 to search left of index
 *
 * @return index if char is contained in buf
 *         -1 if char is not found or invalid inputs
 */
int get_index_for_char(charbuf buf, char c, unsigned int index, int direction);

/**
 * <pre>
 * This function creates a new charbuf that contains the contents of another buffer starting at 
 * the specified index
 * </pre>
 *
 * @param[in] buf The charbuf to be copied from
 * @param[in] index The starting char of char array to be copied
 *
 * @return charbuf copy of tail of buf starting at index
 */
charbuf copy_chars_from_charbuf(charbuf buf, int index);

#endif /* INCLUDE_CHARBUF_H_ */
