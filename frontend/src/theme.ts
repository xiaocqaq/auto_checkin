/** 亮/暗主题的唯一入口。
 *
 *  三态：`system` / `light` / `dark`。**`system` 是默认值**，也是「用户从没选过」的状态 ——
 *  两者故意不做区分：界面上「跟随系统」是一个可以主动选回来的选项，不是一个隐藏的初值。
 *
 *  HeroUI 的 Tailwind 预设里 `darkMode: "class"`，所以成品 CSS 中 `.dark` 那一整套 token
 *  已经在；本文件只决定什么时候把 `dark` 挂到 <html> 上。
 *
 *  首帧那段 class 不由这里设：index.html 的内联脚本必须赶在样式生效前跑完（否则先闪一帧
 *  亮色），而它没法 import 这个模块。两边共用同一份约定 —— **值不是 light/dark 就跟系统** ——
 *  所以存 `system` 和从没存过在首帧脚本眼里是同一件事。
 */
export type ThemeChoice = 'light' | 'dark' | 'system'
export type Theme = 'light' | 'dark'

/** 与本站其它站点（mem_theme / learn-hub-theme）同一命名法。 */
const KEY = 'checkin-theme'

const media = () =>
  typeof window === 'undefined' ? undefined : window.matchMedia?.('(prefers-color-scheme: dark)')

/** 设备当前的亮暗（系统设置、手机日落切换都算在这里）。 */
export const systemTheme = (): Theme => (media()?.matches ? 'dark' : 'light')

/** 用户的选择 → 眼下真正该显示什么。 */
export const resolveTheme = (choice: ThemeChoice): Theme =>
  choice === 'system' ? systemTheme() : choice

/** 存下来的选择。没存过、存坏了、或隐私模式读不到 —— 一律当「跟随系统」。 */
export function storedChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY)
    return v === 'light' || v === 'dark' ? v : 'system'
  } catch {
    return 'system'
  }
}

/** 用户选过没有。只用来区分「这是他自己定的」和「这是系统替他定的」，
 *  例如菜单里要不要给「跟随系统」打勾之外的提示。 */
export const hasExplicitChoice = (): boolean => {
  const v = storedChoice()
  return v === 'light' || v === 'dark'
}

function paint(next: Theme) {
  document.documentElement.classList.toggle('dark', next === 'dark')
}

/** 用户选择了某个模式：改像素 + 落盘。
 *  `system` 也照存 —— 把「跟随系统」这个决定本身记下来，好让菜单下次打开时打勾在它身上。 */
export function setChoice(choice: ThemeChoice) {
  paint(resolveTheme(choice))
  try {
    localStorage.setItem(KEY, choice)
  } catch {
    /* 隐私模式写不进去：本次会话生效即可，别让切换本身失败 */
  }
}

/** 系统主题变了。只有还处在「跟随系统」时才需要重画；选了亮/暗的人不该被系统拖走。 */
export function repaintIfFollowing(): Theme {
  const next = resolveTheme(storedChoice())
  paint(next)
  return next
}
