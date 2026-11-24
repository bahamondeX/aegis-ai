import CoreImage
import Foundation

// Read the authenticator URI from stdin so it never appears in process arguments.
let message = FileHandle.standardInput.readDataToEndOfFile()
guard !message.isEmpty, let filter = CIFilter(name: "CIQRCodeGenerator") else {
    exit(1)
}
filter.setValue(message, forKey: "inputMessage")
filter.setValue("M", forKey: "inputCorrectionLevel")
guard
    let qr = filter.outputImage,
    let image = CIContext().createCGImage(
        qr, from: qr.extent, format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB()
    ),
    let data = image.dataProvider?.data,
    let pixels = CFDataGetBytePtr(data),
    image.bitsPerPixel == 32
else {
    exit(1)
}

for row in 0..<image.height {
    let start = row * image.bytesPerRow
    print((0..<image.width).map { pixels[start + 4 * $0] < 128 ? "1" : "0" }.joined())
}
