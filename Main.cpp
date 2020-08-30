#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <vector>


namespace
{
    using Buffer = std::vector<unsigned char>;
    using FilePtr = std::unique_ptr<FILE, decltype(&fclose)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

    const auto* CERTIFICATE_PATH = "/usr/local/Cellar/python/3.7.5/Frameworks/Python.framework/Versions/3.7/lib/python3.7/test/nokia.pem";
    const std::size_t CERTIFICATE_SUBJECT_LENGTH = 200;
}


void bail(const char* errorMessage)
{
    std::cout << "\n\n" << errorMessage << "\n\n";
    std::abort();
}


int main()
{
    const FilePtr file{fopen(CERTIFICATE_PATH, "r"), fclose};
    if (!file)
    {
        bail("fopen failure");
    }

    X509Ptr x509{PEM_read_X509(file.get(), nullptr, nullptr, nullptr), X509_free};
    if (!x509)
    {
        bail("PEM_read_X509 failure");
    }

    const auto certificateLength = i2d_X509(x509.get(), nullptr);
    if (certificateLength < 0)
    {
        bail("i2d_X509 failure -- length");
    }

    Buffer buffer(certificateLength);
    auto* rawBuffer = buffer.data();
    if (buffer.size() != i2d_X509(x509.get(), &rawBuffer))
    {
        bail("i2d_X509 failure -- serialization");
    }

    rawBuffer = buffer.data();
    x509.reset(d2i_X509(nullptr, const_cast<const unsigned char**>(&rawBuffer), buffer.size()));
    if (!x509)
    {
        bail("d2i_X509 failure");
    }

    const auto* x509Name = X509_get_subject_name(x509.get());
    if (!x509Name)
    {
        bail("X509_get_subject_name failure");
    }

    Buffer x509NameString(CERTIFICATE_SUBJECT_LENGTH + 1);
    static_cast<void>(X509_NAME_oneline(x509Name, reinterpret_cast<char*>(x509NameString.data()), x509NameString.size()));

    std::cout << "\n\nserialization and parsing successful!\n\n"
              << "certificate subject = `"
              << x509NameString.data()
              << "`\n\n";

    return 0;
}
