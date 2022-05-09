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
 * @param[in] len Length of new char array, must be smaller than SIZE_MAX.
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
 * Takes a two charbufs and compares them to each other to determine which is greater
 * in lexicographic order.
 *
 * The NULL buffer is less than any other (non-NULL) buffer.
 *
 * If both buffers are non-NULL, we first compare bytes up to the length
 * of the shorter buffer. If the two buffers differ within that segment
 * they are ordered based on the order within that segment.
 *
 * If both buffers are non-NULL and are the same up to the length of the
 * shorter buffer, the shorter buffer is less than the longer buffer. 
 * </pre>
 *
 * @param[in] buf1 charbuf to be compared
 * @param[in] buf2 charbuf to be compared
 *
 * @return 0 if the buffers contain the same bytes
 *        -1 if buf1 is less than buf2
 *         1 if buf2 is less than buf1
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
 *         SIZE_MAX if char is not found or invalid inputs
 */
size_t get_index_for_char(charbuf buf, char c, size_t index, int direction);

/**
 * <pre>
 * This function creates a new charbuf that contains the contents of another buffer starting at 
 * the specified index. Returns an empty charbuf if index is out of bounds.
 * </pre>
 *
 * @param[in] buf The charbuf to be copied from
 * @param[in] index The starting char of char array to be copied
 *
 * @return charbuf copy of tail of buf starting at index
 */
charbuf copy_chars_from_charbuf(charbuf buf, size_t index);

/**
 * <pre>
 * Takes a struct charbuf and allocates memory of len + 1 then copies chars to the allocated memory.
 * </pre>
 *
 * @param[in] buf The charbuf to be turned into a null terminated sting
 *
 * @return the null terminated sting in buf.chars
 */
unsigned char * null_terminated_string_from_charbuf(charbuf buf);

#endif /* INCLUDE_CHARBUF_H_ */
