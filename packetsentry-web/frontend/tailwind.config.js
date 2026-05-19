/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        industrial: { canvas: "#C0C0C0", steel: "#E4E4E7" },
        pixel: { green: "#00FF41" },
      },
      boxShadow: {
        brutalist: "4px 4px 0px 0px rgba(0,0,0,1)",
      },
    },
  },
  plugins: [],
};
