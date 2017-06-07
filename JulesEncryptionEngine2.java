package million.h2e.phornollit;

public interface JulesEncryptionEngine2 extends JulesEncryptionEngine
{
	byte[] encrypt(String key, byte[] data, int offset, int dataSize, int returnSize);
	byte[] encrypt(byte[] key, byte[] data, int offset, int dataSize, int returnSize);

	byte[] decrypt(String key, byte[] data, int offset, int dataSize, int returnSize);
	byte[] decrypt(byte[] key, byte[] data, int offset, int dataSize, int returnSize);
}
