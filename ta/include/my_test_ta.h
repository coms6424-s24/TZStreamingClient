#ifndef TA_MY_TEST_H
#define TA_MY_TEST_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_MY_TEST_UUID                                    \
    {                                                      \
        0x9aaaf200, 0x2450, 0x11e4,                        \
        {                                                  \
            0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b \
        }                                                  \
    }

/*
 * in	params[0].value.a key size
 */
#define TA_ACIPHER_CMD_GEN_KEY 0

/*
 * in	params[1].memref  input
 * out	params[2].memref  output
 */
#define TA_ACIPHER_CMD_ENCRYPT 1

#endif /*TA_MY_TEST_H*/
