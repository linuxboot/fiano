package uefi

// Visitor represents an operation which can be applied to the Firmware.
// Typically, the Visit function contains a type switch for the different
// firmware types and a default case. For example:
//
// func (v *Example) Visit(f uefi.Firmware) error {
//     switch f := f.(type) {
//
//     case *uefi.File:
//         fmt.Println("f is a file")
//         return f.ApplyChildren(v) // Children are recursed over
//
//     case *uefi.Section:
//         fmt.Println("f is a section")
//         return nil // Children are not visited
//
//     default:
//         // The default action is to recurse over children.
//         return f.ApplyChildren(v)
//     }
// }
type Visitor interface {
	Visit(Firmware) error
}
