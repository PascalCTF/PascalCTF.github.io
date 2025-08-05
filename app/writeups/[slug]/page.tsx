import { Navigation } from "@/components/navigation"
import { writeups } from "@/data/writeups"
import { notFound } from "next/navigation"
import Link from "next/link"
import { ArrowLeft, Calendar, User, Tag } from "lucide-react"

interface WriteupPageProps {
  params: {
    slug: string
  }
}

export function generateStaticParams() {
  return writeups.map((writeup) => ({
    slug: writeup.slug,
  }))
}

export default function WriteupPage({ params }: WriteupPageProps) {
  const writeup = writeups.find((w) => w.slug === params.slug)

  if (!writeup) {
    notFound()
  }

  // Sample challenges data - in a real app this would come from a separate data file
  const challenges = [
    {
      category: "Web",
      challenges: [
        {
          name: "Simple Login",
          difficulty: "Easy",
          points: 100,
          description: "A basic SQL injection challenge to bypass authentication.",
          solution:
            "The login form is vulnerable to SQL injection. Using `admin' OR '1'='1' --` as username bypasses the password check.",
        },
        {
          name: "Cookie Monster",
          difficulty: "Medium",
          points: 200,
          description: "Manipulate cookies to gain admin access.",
          solution:
            "The application stores user role in a cookie. Changing the role cookie value from 'user' to 'admin' grants administrative privileges.",
        },
      ],
    },
    {
      category: "Cryptography",
      challenges: [
        {
          name: "Caesar's Secret",
          difficulty: "Easy",
          points: 100,
          description: "Decode a message encrypted with Caesar cipher.",
          solution: "The message is encrypted with a Caesar cipher with shift 13 (ROT13). Decoding reveals the flag.",
        },
        {
          name: "Base64 Layers",
          difficulty: "Easy",
          points: 150,
          description: "Multiple layers of Base64 encoding hide the flag.",
          solution: "The flag is encoded multiple times with Base64. Decode iteratively until you get readable text.",
        },
      ],
    },
    {
      category: "Binary Exploitation",
      challenges: [
        {
          name: "Stack Overflow",
          difficulty: "Medium",
          points: 300,
          description: "Exploit a buffer overflow vulnerability.",
          solution:
            "The program has a buffer overflow in the input function. Overwrite the return address to jump to the win function.",
        },
      ],
    },
  ]

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Navigation />

      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <Link
          href="/writeups"
          className="inline-flex items-center text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 mb-8"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Writeups
        </Link>

        <article className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="p-8">
            <header className="mb-8">
              <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">{writeup.title}</h1>

              <div className="flex flex-wrap items-center gap-4 text-sm text-gray-600 dark:text-gray-400 mb-4">
                <div className="flex items-center">
                  <User className="w-4 h-4 mr-1" />
                  {writeup.author}
                </div>
                <div className="flex items-center">
                  <Calendar className="w-4 h-4 mr-1" />
                  {writeup.date}
                </div>
              </div>

              <div className="flex flex-wrap gap-2 mb-6">
                {writeup.tags.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200"
                  >
                    <Tag className="w-3 h-3 mr-1" />
                    {tag}
                  </span>
                ))}
              </div>

              <p className="text-lg text-gray-700 dark:text-gray-300 leading-relaxed">{writeup.description}</p>
            </header>

            <div className="prose dark:prose-invert max-w-none">
              <h2>Competition Overview</h2>
              <p>
                PascalCTF Beginners 2025 was designed as an entry-level competition to introduce newcomers to the world
                of Capture The Flag competitions. The event featured challenges across multiple categories, each crafted
                to teach fundamental security concepts while remaining accessible to beginners.
              </p>

              <h2>Challenge Categories</h2>

              {challenges.map((category, categoryIndex) => (
                <div key={categoryIndex} className="mb-8">
                  <h3 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">{category.category}</h3>

                  {category.challenges.map((challenge, challengeIndex) => (
                    <div key={challengeIndex} className="mb-6 p-6 bg-gray-50 dark:bg-gray-700 rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="text-xl font-medium text-gray-900 dark:text-white">{challenge.name}</h4>
                        <div className="flex items-center space-x-3">
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium ${
                              challenge.difficulty === "Easy"
                                ? "bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200"
                                : challenge.difficulty === "Medium"
                                  ? "bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200"
                                  : "bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200"
                            }`}
                          >
                            {challenge.difficulty}
                          </span>
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-400">
                            {challenge.points} pts
                          </span>
                        </div>
                      </div>

                      <p className="text-gray-700 dark:text-gray-300 mb-4">{challenge.description}</p>

                      <div className="bg-white dark:bg-gray-800 p-4 rounded border-l-4 border-blue-500">
                        <h5 className="font-medium text-gray-900 dark:text-white mb-2">Solution:</h5>
                        <p className="text-gray-700 dark:text-gray-300">{challenge.solution}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ))}

              <h2>Key Takeaways</h2>
              <ul>
                <li>Always sanitize user input to prevent injection attacks</li>
                <li>Never trust client-side data like cookies without server-side validation</li>
                <li>Understanding basic cryptographic concepts is essential for security</li>
                <li>Buffer overflows remain a critical vulnerability class in binary exploitation</li>
              </ul>

              <h2>Resources for Learning</h2>
              <p>For those interested in learning more about CTF competitions and cybersecurity, we recommend:</p>
              <ul>
                <li>
                  <a href="https://picoctf.org/" target="_blank" rel="noopener noreferrer">
                    PicoCTF
                  </a>{" "}
                  - Great for beginners
                </li>
                <li>
                  <a href="https://overthewire.org/wargames/" target="_blank" rel="noopener noreferrer">
                    OverTheWire
                  </a>{" "}
                  - Progressive challenges
                </li>
                <li>
                  <a href="https://ctftime.org/" target="_blank" rel="noopener noreferrer">
                    CTFtime
                  </a>{" "}
                  - Competition calendar and team rankings
                </li>
              </ul>
            </div>
          </div>
        </article>
      </main>
    </div>
  )
}
