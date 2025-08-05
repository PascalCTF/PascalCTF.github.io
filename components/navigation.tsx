import Link from "next/link"
import { ThemeSwitcher } from "./theme-switcher"

export function Navigation() {
  return (
    <nav className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <Link href="/" className="flex items-center">
            <div className="w-6 h-6 bg-red-600 rounded-sm mr-2"></div>
            <span className="font-medium text-gray-900 dark:text-white">Blaisone</span>
          </Link>
          <div className="flex items-center space-x-8">
            <Link
              href="/writeups"
              className="text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white font-medium"
            >
              Writeups
            </Link>
            <Link
              href="/members"
              className="text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white font-medium"
            >
              Members
            </Link>
            <Link
              href="/sponsors"
              className="text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white font-medium"
            >
              Sponsors
            </Link>
            <ThemeSwitcher />
          </div>
        </div>
      </div>
    </nav>
  )
}
