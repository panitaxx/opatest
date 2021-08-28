package opatest

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

var badkey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCv9GCKxswe5axmZ0XUVoi2JB6fZWtquTMq+EwIHfqDT6Ch252W
sJNF0XxupVdzxLlGax2enE0i4oKf8fNNylX2cRTvHJxlwdJjwZ2oARYScqacZjA5
JRDDUsuzW9Qqru2fB6lXkgN1Aklzgnf0bkx6CoqwsHBkPVNyts2fpDLFBQIDAQAB
AoGAK4rUIUOU28iGY0kHNMa9SiWiFlvoux5dlTKgzhltFvWrkKJiWxoTN+HhYxgz
jgiOuOhlCg0v4YQgQyiCxytdHhgI+2fwh8upknNMLJdO485wbSe/nOaX1HO49yR/
LAL3RX4+7pjSdlofGzu+mLaactU4M6i2QxBYj1xSfqJkyTkCQQDkFooNmHZV9cLr
8msT3Dp2QpVJ4/hIwLCSPkPJLGfMUBpW/mBSgrBP1WkF5Us1564WEe9gsX6eZur5
rlZewYNbAkEAxXyesM/ZYe1j3AlBOnQ69882vyeXK1oou1pHbKv7zbIgTjnusk5N
GeqQfLvB+9MMLF2XVzqfbnBGoLYs0BMnHwJAAxVi7GghQWw/JF10oSIbEDo6NnOE
icdBG9kHpZKaHKMAmCh8OOFXbNzfvJqq96GYMugvKkl8Arw1dQasWD+ZfQJBAMMz
4futBxcXucwFzdbEioDl7hxWOsMcNAS0QMM24Ac62VnZQ4o1gVprk3Pndt++hVrZ
C72p8WsNSZKTX4owVEsCQHIe9bXtAS8M02ftqHpp4Lvvu5R3WdLV2Jg/tCa/YogM
b6giP1ZPqZArXaaZaUXZrWcsYx956X6wA4RkjrvaG40=
-----END RSA PRIVATE KEY-----`

var goodKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCiLNFozZHCmKQ8WjftXTv5FPcrdd/GTalGGkZ0UdzstZJCGcHO
MKxvP2sqpvUfZsSuHPFqlQq5T/EqjOJWm9zmvhgWcHSea7nWwbakc66lU+qDBJr7
axZZ5l1N0CmuRNcCGvzIG/rKhS6JbQFztqFwrWP3Kce1F+f+75e/hwaLHwIDAQAB
AoGARmk7Ckuma1ymgeWRvqbqMPzfS6lD3O8+/UbPLBWW29cBh11zfbg4RZy9RKl0
Z4vQ/N9oGaRYIZkJ1jWQ15WYVI1b/78A4005aRZ9pXQ0mor2vVFNU9711/Ksu023
IDKwjYSuNUPSv+RgEJQS0u9dzUW7X7JaTBWSJAu8zC/tufECQQDG0jHGkpex2nyg
gTT4G65636kjxPeB7LwBc/aSKfaj67NuuwgLL5GBP1yKRASpGfs0p5cpP4GsKz4n
2D9U36nVAkEA0NCieQqnZKDyO8d5lCKjpc1TxNl+3GOxblNA3yYd/3PhKycVbbuE
POvo69ms3EFLcSL2tDOksajovvWb+NeHIwJBAIVPlQ6HZm1biWr5l7Gwpeo/o6KX
RDn6qQj0X2Ub/ANnXDWn9LnDWHXoLT2MY++auyRQJvwCWAlAKXn/9l8LZU0CQBHk
zwdwUkfdQuS8gz6eeUeMANGtkaFxKZM6ryRwL8HkPDdmcf+lQf+2d48+aAG31q8r
P9jRVBulTcyPX35DeeECQQC9UpE4PIPgXR0lp11uaPCuaLs4UO7R3ZFxXUGuLLis
3o9FKqAL1aUPhKzrF9vSQ8A8Ib2EZ342yVGp1l0EvKpQ
-----END RSA PRIVATE KEY-----`

func TestPublishBundleRSA(t *testing.T) {
	buff := new(bytes.Buffer)
	err := PublishBundleRSA(goodKey, buff)
	assert.NoError(t, err)
}

func TestPublishBundleRSABad(t *testing.T) {
	buff := new(bytes.Buffer)
	err := PublishBundleRSA(badkey, buff)
	assert.NoError(t, err)
}

func TestPublishBundleRSAFile(t *testing.T) {
	buff := new(bytes.Buffer)
	err := PublishBundleRSA("test.pem", buff)
	assert.NoError(t, err)
}
