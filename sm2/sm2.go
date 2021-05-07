package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"github.com/ZZMarquis/gm/sm3"
	"github.com/ZZMarquis/gm/util"
	"hash"
	"io"
	"math/big"
)

const (
	BitSize = 256
	// KeyBytes 代表秘钥的字节长度，其中加7整除8其实是“向上取整”，用以兼容基础域位数不是8的整数倍的情况。
	KeyBytes = (BitSize + 7) / 8
	// UnCompress 代表椭圆曲线上的点采用“未压缩”的形式存储，占1个字节，详见国标1-4.1.(b)的定义。
	UnCompress = 0x04
)

type Sm2CipherTextType int32

const (
	// [GM/T 0009-2012]标准规定的顺序
	C1C2C3 Sm2CipherTextType = 1
	//C1C3C2 代表新标准[GB/T 32918-2016]的密文顺序
	C1C3C2 Sm2CipherTextType = 2
)

var (
	// sm2H 代表SM2推荐曲线的余因子h=1
	// 椭圆曲线方程符合 y^2 = x^3 - 3x + b （mod p）
	sm2H = new(big.Int).SetInt64(1)
	// sm2SignDefaultUserID 代表sm2算法默认的加密操作用户A的ID编码(详见国标5-A.1)和SM2使用规范(GB/T 35276-2017第10部分)
	sm2SignDefaultUserId = []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

// sm2P256V1 代表国密SM2推荐参数定义的椭圆曲线

var sm2P256V1 P256V1Curve

// P256V1Curve 代表国密SM2推荐参数定义的椭圆曲线:
// (1) 素数域256位椭圆曲线
// (2) 曲线方程为 Y^2 = X^3 + aX + b
// (3) 其他参数: p, a, b, n, Gx, Gy 详见国标SM2推荐曲线参数
// (4) 在GO语言标准库通用椭圆曲线参数类elliptic.CurveParams的基础上增加了参数a的属性
// (5) 由于SM2推荐曲线符合a=p-3, 所以上述曲线可简化为等价曲线 Y^2 = X^3 - 3X + b (mod p),
//这里用

type P256V1Curve struct {
	*elliptic.CurveParams //使用标准库
	A                     *big.Int
}

// PublicKey 代表SM2算法的公钥类:
// (1) X,Y 为P点（有限素数域上基点G的D倍点)坐标
// (2) Curve 为SM2算法的椭圆曲线
type PublicKey struct {
	X, Y  *big.Int
	Curve P256V1Curve
}

//PrivateKey 代表SM2算法的私钥类:
// (1) D代表公钥P点相对于基点G的倍数
// (2) Curve 为SM2算法的椭圆曲线
type PrivateKey struct {
	D     *big.Int
	Curve P256V1Curve
}

type sm2Signature struct {
	R, S *big.Int
}

type sm2CipherC1C3C2 struct {
	X, Y *big.Int
	C3   []byte
	C2   []byte
}

type sm2CipherC1C2C3 struct {
	X, Y *big.Int
	C2   []byte
	C3   []byte
}

func init() {
	// init() 初始化国密SM2推荐参数计算得出的椭圆曲线。
	initSm2P256V1()
}

func initSm2P256V1() {
	//使用GB/T ３２９１８．５—２０１７参数
	sm2P, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2N, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2Gx, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256V1.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256-V1"}
	sm2P256V1.P = sm2P
	sm2P256V1.A = sm2A
	sm2P256V1.B = sm2B
	sm2P256V1.N = sm2N
	sm2P256V1.Gx = sm2Gx
	sm2P256V1.Gy = sm2Gy
	sm2P256V1.BitSize = BitSize
}

//
func GetSm2P256V1() P256V1Curve {
	return sm2P256V1
}

// @title    GenerateKey
// @description   为国密SM2生成秘钥对
//(1) 利用GO语言标准包crypto/rand生成随机数rand（安全随机数问题）;
//(2) 将SM2推荐曲线参数和随机数rand输入GO语言标准包crypto/elliptic的公钥对生成方法GenerateKey()，生成密钥对核心参数(priv, x, y);
//(3) 根据PublicKey类和PrivateKey类的定义生成公钥和私钥的实例，并将上述核心参数赋值给实例各相应属性以完成初始化.
// @param     rand
// @return    PrivateKey  PublicKey
func GenerateKey(rand io.Reader) (*PrivateKey, *PublicKey, error) {
	priv, x, y, err := elliptic.GenerateKey(sm2P256V1, rand) //package
	if err != nil {
		return nil, nil, err
	}
	privateKey := new(PrivateKey)
	privateKey.Curve = sm2P256V1
	privateKey.D = new(big.Int).SetBytes(priv) //倍数
	publicKey := new(PublicKey)
	publicKey.Curve = sm2P256V1
	publicKey.X = x
	publicKey.Y = y
	return privateKey, publicKey, nil
}

// @title    RawBytesToPublicKey
// @description   将字节数组形式的原始格式数据转化为SM2公钥的函数
// @param     公钥字节数组
// @return    publicKey
func RawBytesToPublicKey(bytes []byte) (*PublicKey, error) {
	if len(bytes) != KeyBytes*2 {
		return nil, errors.New("Public key raw bytes length must be " + string(KeyBytes*2))
	}
	publicKey := new(PublicKey)
	publicKey.Curve = sm2P256V1
	publicKey.X = new(big.Int).SetBytes(bytes[:KeyBytes])
	publicKey.Y = new(big.Int).SetBytes(bytes[KeyBytes:])
	return publicKey, nil
}

// @title    RawBytesToPrivateKey
// @description   将字节数组形式的原始格式数据转化为SM2私钥的函数
// @param     私钥字节数组
// @return    privateKey
func RawBytesToPrivateKey(bytes []byte) (*PrivateKey, error) {
	if len(bytes) != KeyBytes {
		return nil, errors.New("Private key raw bytes length must be " + string(KeyBytes))
	}
	privateKey := new(PrivateKey)
	privateKey.Curve = sm2P256V1
	privateKey.D = new(big.Int).SetBytes(bytes) //变成大端整数
	return privateKey, nil
}

// @title    GetUnCompressBytes
// @description   为获取未压缩字节数组格式存储的公钥
// @param     PublicKey 未压缩的公钥字节数组
// @return    公钥字节数组
func (pub *PublicKey) GetUnCompressBytes() []byte {
	xBytes := bigIntTo32Bytes(pub.X)
	yBytes := bigIntTo32Bytes(pub.Y)
	xl := len(xBytes)
	yl := len(yBytes)

	raw := make([]byte, 1+KeyBytes*2) //65
	raw[0] = UnCompress               //0x04
	//x坐标写入raw[:33], 将y坐标写入raw[33:]
	if xl > KeyBytes {
		copy(raw[1:1+KeyBytes], xBytes[xl-KeyBytes:])
	} else if xl < KeyBytes {
		copy(raw[1+(KeyBytes-xl):1+KeyBytes], xBytes)
	} else {
		copy(raw[1:1+KeyBytes], xBytes)
	}

	if yl > KeyBytes {
		copy(raw[1+KeyBytes:], yBytes[yl-KeyBytes:])
	} else if yl < KeyBytes {
		copy(raw[1+KeyBytes+(KeyBytes-yl):], yBytes)
	} else {
		copy(raw[1+KeyBytes:], yBytes)
	}
	return raw
}

// @title    GetRawBytes
// @description   返回字节数组格式存储的公钥的方法
// @param     PublicKey 未压缩的公钥字节数组
// @return    公钥字节数组
func (pub *PublicKey) GetRawBytes() []byte {
	raw := pub.GetUnCompressBytes()
	return raw[1:]
}

// @title    GetRawBytes
// @description   获得字节数组格式存储的私钥
// @param     PrivateKey 私钥
// @return    私钥字节数组
func (pri *PrivateKey) GetRawBytes() []byte {
	dBytes := bigIntTo32Bytes(pri.D)
	dl := len(dBytes)
	if dl > KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw, dBytes[dl-KeyBytes:])
		return raw
	} else if dl < KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw[KeyBytes-dl:], dBytes)
		return raw
	} else {
		return dBytes
	}
}

// @title    CalculatePubKey
// @description   根据椭圆曲线、基点G、私钥(D倍数)推算公钥(倍点P)
// @param     PrivateKey 私钥
// @return    pub 公钥
func CalculatePubKey(priv *PrivateKey) *PublicKey {
	pub := new(PublicKey)
	pub.Curve = priv.Curve
	pub.X, pub.Y = priv.Curve.ScalarBaseMult(priv.D.Bytes())
	return pub
}

// @title    nextK
// @description  为生成[rnd, max)范围内随机整数的函数:
// @param     rnd 随机数 max
// @return    随机数
func nextK(rnd io.Reader, max *big.Int) (*big.Int, error) {
	intOne := new(big.Int).SetInt64(1)
	var k *big.Int
	var err error
	for {
		k, err = rand.Int(rnd, max)
		if err != nil {
			return nil, err
		}
		if k.Cmp(intOne) >= 0 {
			return k, err
		}
	}
}

// @title    xor
// @description  将国标3-6.1.A5和3-6.1.A6两步结合到一起的异或函数,
// @param     data 为输入明文消息M kdfOut 私钥派生函数输出缓存buf[]
// @param     dRemaining KDF()函数中标注输入消息数组encData[]阶段性“读”动作读取的字节数组元素个数
// @return    随机数
func xor(data []byte, kdfOut []byte, dRemaining int) {
	for i := 0; i != dRemaining; i++ {
		data[i] ^= kdfOut[i]
	}
}

// 表示SM2 Key的大数比较小时，直接通过Bytes()函数得到的字节数组可能不够32字节，这个时候要补齐成32字节
func bigIntTo32Bytes(bn *big.Int) []byte {
	byteArr := bn.Bytes()
	byteArrLen := len(byteArr)
	if byteArrLen == KeyBytes {
		return byteArr
	}
	byteArr = append(make([]byte, KeyBytes-byteArrLen), byteArr...)
	return byteArr
}

// @title    kdf?
// @description 为SM2公钥加密算法中调用秘钥派生函数的操作步骤（国标4-6.1.A5）
// @param   digest 按照哈希摘要字节长度创设缓存切片buf[]
//// c1x c1y 以公钥P的k倍点坐标(c1x, c1y)和输入明文消息M(长度为klen位)为输入参数
//// (3) 按照国标4-5.4.3定义的秘钥派生函KDF()和国标第4-6.1.A5规定的算法推算中间变量t
//// (4) t=KDF(c1x||c1y, klen), 该算法核心是迭代调用Hash(c1x||c1y||ct)，其中:
////     (a) ct为32位整数计数器, 从1起算
////     (b) 调用次数为klen/v向上取整次
////     (c) v代表哈希摘要的位数长度(SM3为256位)
////     (d) 最后一次调用若明文M剩余长度小于v, 则取有值的字节
//// (5) C2=M^t, 即通过xor()在计算中间变量t的过程中将中间结果与M的对应字节进行异或运算
// @return    随机数
func kdf(digest hash.Hash, c1x *big.Int, c1y *big.Int, encData []byte) {
	bufSize := 4
	if bufSize < digest.Size() {
		bufSize = digest.Size()
	}
	buf := make([]byte, bufSize)

	encDataLen := len(encData)
	c1xBytes := bigIntTo32Bytes(c1x)
	c1yBytes := bigIntTo32Bytes(c1y)
	off := 0
	ct := uint32(0)
	for off < encDataLen {
		digest.Reset()
		digest.Write(c1xBytes)
		digest.Write(c1yBytes)
		ct++
		binary.BigEndian.PutUint32(buf, ct)
		digest.Write(buf[:4])
		tmp := digest.Sum(nil)
		copy(buf[:bufSize], tmp[:bufSize])

		xorLen := encDataLen - off
		if xorLen > digest.Size() {
			xorLen = digest.Size()
		}
		xor(encData[off:], buf, xorLen) //C2=M^t, 即通过xor()在计算中间变量t的过程中将中间结果与M的对应字节进行异或运算
		off += xorLen
	}
}

// @title    notEncrypted
// @description  判断 C2与输入消息M每个字节是否都相等，
//就意味着在3-6.1.A6进行异或计算(C2=M^t)时，中间变量t所有字节均为0。
//是的话应当重新选择随机数k
// @param      encData C2 in 输入消息M
func notEncrypted(encData []byte, in []byte) bool {
	encDataLen := len(encData)
	for i := 0; i != encDataLen; i++ {
		if encData[i] != in[i] {
			return false
		}
	}
	return true
}

// @title    Encrypt
// @description  为SM2加密函数
// @param     pub 公钥 kdfOut
// @param     in 明文消息字节数组 cipherTextType 密文类别标识
// @return    result 密文
func Encrypt(pub *PublicKey, in []byte, cipherTextType Sm2CipherTextType) ([]byte, error) {
	c2 := make([]byte, len(in))
	copy(c2, in)
	var c1 []byte
	digest := sm3.New()
	var kPBx, kPBy *big.Int
	for {
		k, err := nextK(rand.Reader, pub.Curve.N) //生成随机数k, k属于区间[1,N-1]
		if err != nil {
			return nil, err
		}
		kBytes := k.Bytes()
		c1x, c1y := pub.Curve.ScalarBaseMult(kBytes) //生成倍点C1=kG=(c1x, c1y)
		c1 = elliptic.Marshal(pub.Curve, c1x, c1y)   //将公钥曲线与C1点的坐标参数序列化。

		kPBx, kPBy = pub.Curve.ScalarMult(pub.X, pub.Y, kBytes) //kPB=(kPBx, kPBy)
		kdf(digest, kPBx, kPBy, c2)                             //调用改进后的秘钥派生函数kdf(), 生成C2

		if !notEncrypted(c2, in) {
			break //若中间变量t全部字节均为0则重启加密运算(详见国标4-6.1.A5)

		}
	}
	//C3=Hash(x2||M||y2)详见国标4-6.1.A7
	digest.Reset()
	digest.Write(bigIntTo32Bytes(kPBx))
	digest.Write(in)
	digest.Write(bigIntTo32Bytes(kPBy))
	c3 := digest.Sum(nil)
	// 根据密文格式标识的选择输出密文(C1C3C2新国准，或C1C2C3旧国标)

	c1Len := len(c1)
	c2Len := len(c2)
	c3Len := len(c3)
	result := make([]byte, c1Len+c2Len+c3Len)
	if cipherTextType == C1C2C3 {
		copy(result[:c1Len], c1)
		copy(result[c1Len:c1Len+c2Len], c2)
		copy(result[c1Len+c2Len:], c3)
	} else if cipherTextType == C1C3C2 {
		copy(result[:c1Len], c1)
		copy(result[c1Len:c1Len+c3Len], c3)
		copy(result[c1Len+c3Len:], c2)
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
	return result, nil
}

// @title    Decrypt
// @description  解密(国标4-7.1)的函数
// @param     priv 私钥
// @param     in 密文 cipherTextType 密文类别标识
// @return    result 明文

func Decrypt(priv *PrivateKey, in []byte, cipherTextType Sm2CipherTextType) ([]byte, error) {
	c1Len := ((priv.Curve.BitSize+7)>>3)*2 + 1 // 根据算法字长读取C1
	c1 := make([]byte, c1Len)
	copy(c1, in[:c1Len])
	c1x, c1y := elliptic.Unmarshal(priv.Curve, c1) // 读取C1点坐标(c1x, c1y)，并校验是否位于曲线上(标准库方法elliptic.Unmarshal()内部调用)
	//	// 校验S点是否为无穷远点(SM2推荐曲线h为1，S点即为C1点, 本步骤可忽略)
	sx, sy := priv.Curve.ScalarMult(c1x, c1y, sm2H.Bytes())
	if util.IsEcPointInfinity(sx, sy) {
		return nil, errors.New("[h]C1 at infinity")
	}
	c1x, c1y = priv.Curve.ScalarMult(c1x, c1y, priv.D.Bytes()) // 根据私钥(priv.D)和曲线计算倍点[priv.D]C1=(c1x, c1y)
	// 根据密文格式，分别读取C2和C3
	digest := sm3.New()
	c3Len := digest.Size()
	c2Len := len(in) - c1Len - c3Len
	c2 := make([]byte, c2Len)
	c3 := make([]byte, c3Len)
	if cipherTextType == C1C2C3 {
		copy(c2, in[c1Len:c1Len+c2Len])
		copy(c3, in[c1Len+c2Len:])
	} else if cipherTextType == C1C3C2 {
		copy(c3, in[c1Len:c1Len+c3Len])
		copy(c2, in[c1Len+c3Len:])
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
	// 采用改造后的kdf()函数，计算并获取解密后的明文消息M'=C2^t(国标4-7.1.B4-B5)
	kdf(digest, c1x, c1y, c2)

	digest.Reset()
	digest.Write(bigIntTo32Bytes(c1x))
	digest.Write(c2)
	digest.Write(bigIntTo32Bytes(c1y))
	newC3 := digest.Sum(nil)
	// 将u与C3逐位比较(国标4-7.1.B6-2)

	if !bytes.Equal(newC3, c3) {
		return nil, errors.New("invalid cipher text")
	}
	return c2, nil
}

func MarshalCipher(in []byte, cipherTextType Sm2CipherTextType) ([]byte, error) {
	byteLen := (sm2P256V1.Params().BitSize + 7) >> 3
	c1x := make([]byte, byteLen)
	c1y := make([]byte, byteLen)
	c2Len := len(in) - (1 + byteLen*2) - sm3.DigestLength
	c2 := make([]byte, c2Len)
	c3 := make([]byte, sm3.DigestLength)
	pos := 1

	copy(c1x, in[pos:pos+byteLen])
	pos += byteLen
	copy(c1y, in[pos:pos+byteLen])
	pos += byteLen
	nc1x := new(big.Int).SetBytes(c1x)
	nc1y := new(big.Int).SetBytes(c1y)

	if cipherTextType == C1C2C3 {
		copy(c2, in[pos:pos+c2Len])
		pos += c2Len
		copy(c3, in[pos:pos+sm3.DigestLength])
		result, err := asn1.Marshal(sm2CipherC1C2C3{nc1x, nc1y, c2, c3})
		if err != nil {
			return nil, err
		}
		return result, nil
	} else if cipherTextType == C1C3C2 {
		copy(c3, in[pos:pos+sm3.DigestLength])
		pos += sm3.DigestLength
		copy(c2, in[pos:pos+c2Len])
		result, err := asn1.Marshal(sm2CipherC1C3C2{nc1x, nc1y, c3, c2})
		if err != nil {
			return nil, err
		}
		return result, nil
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
}

func UnmarshalCipher(in []byte, cipherTextType Sm2CipherTextType) (out []byte, err error) {
	if cipherTextType == C1C2C3 {
		cipher := new(sm2CipherC1C2C3)
		_, err = asn1.Unmarshal(in, cipher)
		if err != nil {
			return nil, err
		}
		c1xBytes := bigIntTo32Bytes(cipher.X)
		c1yBytes := bigIntTo32Bytes(cipher.Y)
		c1xLen := len(c1xBytes)
		c1yLen := len(c1yBytes)
		c2Len := len(cipher.C2)
		c3Len := len(cipher.C3)
		result := make([]byte, 1+c1xLen+c1yLen+c2Len+c3Len)
		pos := 0
		result[pos] = UnCompress
		pos += 1
		copy(result[pos:pos+c1xLen], c1xBytes)
		pos += c1xLen
		copy(result[pos:pos+c1yLen], c1yBytes)
		pos += c1yLen
		copy(result[pos:pos+c2Len], cipher.C2)
		pos += c2Len
		copy(result[pos:pos+c3Len], cipher.C3)
		return result, nil
	} else if cipherTextType == C1C3C2 {
		cipher := new(sm2CipherC1C3C2)
		_, err = asn1.Unmarshal(in, cipher)
		if err != nil {
			return nil, err
		}
		c1xBytes := bigIntTo32Bytes(cipher.X)
		c1yBytes := bigIntTo32Bytes(cipher.Y)
		c1xLen := len(c1xBytes)
		c1yLen := len(c1yBytes)
		c2Len := len(cipher.C2)
		c3Len := len(cipher.C3)
		result := make([]byte, 1+c1xLen+c1yLen+c2Len+c3Len)
		pos := 0
		result[pos] = UnCompress
		pos += 1
		copy(result[pos:pos+c1xLen], c1xBytes)
		pos += c1xLen
		copy(result[pos:pos+c1yLen], c1yBytes)
		pos += c1yLen
		copy(result[pos:pos+c3Len], cipher.C3)
		pos += c3Len
		copy(result[pos:pos+c2Len], cipher.C2)
		return result, nil
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
}

func getZ(digest hash.Hash, curve *P256V1Curve, pubX *big.Int, pubY *big.Int, userId []byte) []byte {
	digest.Reset()

	userIdLen := uint16(len(userId) * 8)
	var userIdLenBytes [2]byte
	binary.BigEndian.PutUint16(userIdLenBytes[:], userIdLen)
	digest.Write(userIdLenBytes[:])
	if userId != nil && len(userId) > 0 {
		digest.Write(userId)
	}

	digest.Write(bigIntTo32Bytes(curve.A))
	digest.Write(bigIntTo32Bytes(curve.B))
	digest.Write(bigIntTo32Bytes(curve.Gx))
	digest.Write(bigIntTo32Bytes(curve.Gy))
	digest.Write(bigIntTo32Bytes(pubX))
	digest.Write(bigIntTo32Bytes(pubY))
	return digest.Sum(nil)
}

func calculateE(digest hash.Hash, curve *P256V1Curve, pubX *big.Int, pubY *big.Int, userId []byte, src []byte) *big.Int {
	z := getZ(digest, curve, pubX, pubY, userId)

	digest.Reset()
	digest.Write(z)
	digest.Write(src)
	eHash := digest.Sum(nil)
	return new(big.Int).SetBytes(eHash)
}

func MarshalSign(r, s *big.Int) ([]byte, error) {
	result, err := asn1.Marshal(sm2Signature{r, s})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func UnmarshalSign(sign []byte) (r, s *big.Int, err error) {
	sm2Sign := new(sm2Signature)
	_, err = asn1.Unmarshal(sign, sm2Sign)
	if err != nil {
		return nil, nil, err
	}
	return sm2Sign.R, sm2Sign.S, nil
}

func SignToRS(priv *PrivateKey, userId []byte, in []byte) (r, s *big.Int, err error) {
	digest := sm3.New()
	pubX, pubY := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	if userId == nil {
		userId = sm2SignDefaultUserId
	}
	e := calculateE(digest, &priv.Curve, pubX, pubY, userId, in)

	intZero := new(big.Int).SetInt64(0)
	intOne := new(big.Int).SetInt64(1)
	for {
		var k *big.Int
		var err error
		for {
			k, err = nextK(rand.Reader, priv.Curve.N)
			if err != nil {
				return nil, nil, err
			}
			px, _ := priv.Curve.ScalarBaseMult(k.Bytes())
			r = util.Add(e, px)
			r = util.Mod(r, priv.Curve.N)

			rk := new(big.Int).Set(r)
			rk = rk.Add(rk, k)
			if r.Cmp(intZero) != 0 && rk.Cmp(priv.Curve.N) != 0 {
				break
			}
		}

		dPlus1ModN := util.Add(priv.D, intOne)
		dPlus1ModN = util.ModInverse(dPlus1ModN, priv.Curve.N)
		s = util.Mul(r, priv.D)
		s = util.Sub(k, s)
		s = util.Mod(s, priv.Curve.N)
		s = util.Mul(dPlus1ModN, s)
		s = util.Mod(s, priv.Curve.N)

		if s.Cmp(intZero) != 0 {
			break
		}
	}

	return r, s, nil
}

// 签名结果为DER编码的字节数组
func Sign(priv *PrivateKey, userId []byte, in []byte) ([]byte, error) {
	r, s, err := SignToRS(priv, userId, in)
	if err != nil {
		return nil, err
	}

	return MarshalSign(r, s)
}

func VerifyByRS(pub *PublicKey, userId []byte, src []byte, r, s *big.Int) bool {
	intOne := new(big.Int).SetInt64(1)
	if r.Cmp(intOne) == -1 || r.Cmp(pub.Curve.N) >= 0 {
		return false
	}
	if s.Cmp(intOne) == -1 || s.Cmp(pub.Curve.N) >= 0 {
		return false
	}

	digest := sm3.New()
	if userId == nil {
		userId = sm2SignDefaultUserId
	}
	e := calculateE(digest, &pub.Curve, pub.X, pub.Y, userId, src)

	intZero := new(big.Int).SetInt64(0)
	t := util.Add(r, s)
	t = util.Mod(t, pub.Curve.N)
	if t.Cmp(intZero) == 0 {
		return false
	}

	sgx, sgy := pub.Curve.ScalarBaseMult(s.Bytes())
	tpx, tpy := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, y := pub.Curve.Add(sgx, sgy, tpx, tpy)
	if util.IsEcPointInfinity(x, y) {
		return false
	}

	expectedR := util.Add(e, x)
	expectedR = util.Mod(expectedR, pub.Curve.N)
	return expectedR.Cmp(r) == 0
}

// 输入签名须为DER编码的字节数组
func Verify(pub *PublicKey, userId []byte, src []byte, sign []byte) bool {
	r, s, err := UnmarshalSign(sign)
	if err != nil {
		return false
	}

	return VerifyByRS(pub, userId, src, r, s)
}
