import * as React from "react"

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'secondary' | 'outline'
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', ...props }, ref) => {
    const baseClasses = "inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none ring-offset-background"
    
    const variants = {
      default: "bg-blue-600 text-white hover:bg-blue-700 h-10 py-2 px-4",
      secondary: "bg-gray-100 text-gray-900 hover:bg-gray-200 h-10 py-2 px-4",
      outline: "border border-gray-300 bg-white hover:bg-gray-50 h-10 py-2 px-4"
    }

    return (
      <button
        className={`${baseClasses} ${variants[variant]} ${className || ''}`}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button }