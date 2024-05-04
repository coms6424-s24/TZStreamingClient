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

#define TA_RSA_CMD_GENKEYS 0
#define TA_RSA_CMD_ENCRYPT 1
#define TA_RSA_CMD_DECRYPT 2
#define TA_RSA_CMD_GET_PUB_KEY 3

#endif /*TA_MY_TEST_H*/
